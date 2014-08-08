#!/usr/bin/env python
#
# Copyright (C) 2014  Anthony King
# Copyright (C) 2014  CyboLabs
# Copyright (C) 2014  GermainZ
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Generate an incremental patch to work on all aosp based recoveries.

This is a standalone script which takes two zips, and generates an OTA for
roms, mods, or gapps.
"""

from __future__ import print_function, absolute_import

__author__ = "Anthony 'Cybojenix' King"
__program__ = "DeltaJen"
__version__ = "0.1a1"

from hashlib import sha1
from os import path, devnull, name as os_name
from re import search as re_search
from subprocess import Popen, STDOUT
from tempfile import NamedTemporaryFile
from time import localtime, time
from zipfile import ZipFile, ZIP_DEFLATED, ZipInfo

# bsdiff4 for python yields better results than stock bsdiff
try:
    from bsdiff4 import diff as bs_diff
except ImportError:
    bs_patch = None


class Hooks(object):
    """Base class for the DeltaJen Hooks, to accommodate for custom zips.

    Subclass this if you are using a non standard device that usually
    requires files being changed during a standard flash or at run time.
    """

    def __init__(self, main):
        """Initialise the Hook class.

        Args:
            main (DeltaJen): this is a copy of the DeltaJen class instance.
                Through this, the user can access all variables and functions
                if needed. Refer to the DeltaJen documentation for a list of
                functions and variables

        Attributes:
            _boot_info_cache (tuple of strings): tuple containing the boot
                partition's location and its type. For example:
                    ('/dev/block/platform/msm_sdcc.1/by-name/boot', 'emmc')
            _system_info_cache (tuple of strings): typle containing the system
                partition's location and its type. For example:
                    ('/dev/block/platform/msm_sdcc.1/by-name/system', 'ext4')
        """
        self.main = main
        self._boot_info_cache = None
        self._system_info_cache = None

    def to_copy(self):
        """Return a list of files that should be copied without being patched.

        An example of this is for unified devices, where different
        variants have extra folders that are copied to system based
        on which model the device is.
        """
        return []

    def extra_files(self):
        """Return a list of files that are not in /system or boot.img.

        An example of this is for unified devices, where different variants
        use different kernels.
        """
        return []

    def pre_flash_script(self):
        """Return a list of edify commands to be called before patching.

        An example of this is for custom handling of a partition.
        """
        return []

    def post_flash_script(self):
        """Return a list of edify commands to be called after patching.

        An example of this is for unified devices, where different variants
        use different files.
        """
        return []

    def boot_info(self):
        """Find and return the boot partition info.

        If not correctly detected for your device, overwrite this
        to return the correct value.
        """
        if self._boot_info_cache is not None:
            return self._boot_info_cache

        print("WARNING: boot information not supplied.")
        edify = self.main.get_edify()
        if edify.find('assert(package_extract_file("boot.img", ' +
                      '"/tmp/boot.img")') != -1:
            print("BML boot info found")
            pos = edify.find('write_raw_image("/tmp/boot.img"') + 34
            end = edify.find('"),', pos)
            dev = edify[pos:end]
            self._boot_info_cache = (dev, "bml")
        elif edify.find('package_extract_file("boot.img", ' +
                        '"/tmp/boot.img");') != -1:
            print("MTD boot info found")
            pos = edify.find('write_raw_image("/tmp/boot.img"') + 34
            end = edify.find('");', pos)
            dev = edify[pos:end]
            self._boot_info_cache = (dev, "mtd")
        elif edify.find('package_extract_file("boot.img", "') != -1:
            print("EMMC boot info found")
            pos = edify.find('package_extract_file("boot.img"') + 34
            end = edify.find('");', pos)
            dev = edify[pos:end]
            self._boot_info_cache = (dev, "emmc")
        else:
            print("WARNING: boot info could not be found.")
            self._boot_info_cache = ()
        return self._boot_info_cache

    def system_info(self):
        """Find and return the system partition info.

        If not correctly detected for your device, overwrite this
        to return the correct value.
        """
        if self._system_info_cache is not None:
            return self._system_info_cache
        print("WARNING: system partition information not supplied")

        edify = self.main.get_edify()
        mount = re_search(r'mount\("(\S+)"\s*,\s*' +
                          '"(\S+)"\s*,\s*"(\S+)"\s*,\s*"/system"\);', edify)
        if not mount:
            self._system_info_cache = ()
            print("WARNING: system mount info could not be found.")
        else:
            print("Detected system mount info.")
            part = mount.group(1)
            dev = mount.group(3)
            self._system_info_cache = (dev, part)
        return self._system_info_cache


class Edify(object):
    """Class for common edify methods."""

    def apply_patch_check(self, f_name, *sha):
        """Check that the given file (or mount point reference) has
        one of the given sha1 hashes.

        Args:
            f_name (str): File name and path of the file to check.
            sha (str): tuple of sha1sums to check the file against.
        """
        cmd = 'apply_patch_check("%s"'
        cmd += ''.join([', "%s"' % i for i in sha])
        cmd += ') || abort("\\"%s\\" has unexpected contents.");'
        cmd = cmd % (f_name, f_name)
        return cmd

    def ui_print(self, message):
        """Log a message to the screen

        Args:
            message (str): message to display on screen.
        """
        cmd = 'ui_print("%s");'
        cmd = cmd % message
        return cmd

    def apply_patch(self, b_name, n_name, n_size, n_sha, *patch_pairs):
        """Apply binary patches (in *patch_pairs) to the given base
        file (b_name) to produce the new file (n_name)

        Args:
            b_name (str): File name and path of the base file.
            n_name (str): File name and path of the new file.
                Can be "-" to overwrite the base file.
            n_size (int): Size of the new file.
            n_sha (str): sha1sum of the new file
            patch_pairs (str): tuple of the base file sha1sum,
                and the file name of the patch file.
        """
        if len(patch_pairs) % 2 != 0 or len(patch_pairs) == 0:
            raise ValueError("bad patches given to ApplyPatch")
        cmd = 'apply_patch("%s", "%s", %s, %d'
        cmd = cmd % (b_name, n_name, n_sha, n_size)
        for i in range(0, len(patch_pairs), 2):
            cmd += ', %s, package_extract_file("%s")'
            cmd = cmd % patch_pairs[i:i+2]
        cmd += ');'
        return cmd

    def mount(self, fs_type, part_type, device, mnt_pnt):
        """Mount the partition with given mount point (mnt_pnt)

        Args:
            fs_type (str): File system type (e.g. ext4)
            part_type (str): Partition type (e.g. EMMC)
            device (str): Partition device location
            mnt_pnt (str): mount point
        """
        cmd = 'mount("%s", "%s", "%s", "%s");'
        cmd = cmd % (fs_type, part_type, device, mnt_pnt)
        return cmd

    def unmount(self, mnt_pnt):
        """Unmount the partition with given mount point (mnt_pnt)

        Args:
            mnt_pnt (str): mount point
        """
        cmd = 'unmount("%s");'
        cmd = cmd % mnt_pnt
        return cmd

    def delete(self, file_list):
        """Delete all files in file_list."""
        cmd = 'delete('
        cmd += ', '.join(['"%s"' % i for i in file_list])
        cmd += ');'
        return cmd


class DeltaJen(object):
    """Generate an incremental update based off two zips."""

    def __init__(self, base_zip, input_zip, output_zip,
                 hooks=Hooks, edify=Edify, verbose=False):
        """Initialize the DeltaJen class.

        Args:
            base_zip (str): Location of the original zip to diff against.
            input_zip (str): Location of the new zip to diff with.
            output_zip (str): Location of the zip to be generated.

        Keyword args:
            hooks (Hooks): provide extended class if necessary.
            edify (Edify): provide extended class if necessary.
            verbose (bool): makes the script more verbose, useful for
                debugging.

        Raises:
            FileNotFound: An error occurred trying to find a supplied file.
        """
        if not path.isfile(base_zip):
            raise FileNotFound(base_zip)
        if not path.isfile(input_zip):
            raise FileNotFound(input_zip)

        self.base_zip = ZipFile(base_zip)
        self.input_zip = ZipFile(input_zip)
        self.output_zip = ZipFile(output_zip, 'w', ZIP_DEFLATED)

        self.base_ptr = None
        self.input_ptr = None
        self.verbose = verbose

        self.edify = edify()
        self.hooks = hooks(self)

        self.part_types = {
            "bml": "BML",
            "ext2": "EMMC",
            "ext3": "EMMC",
            "ext4": "EMMC",
            "emmc": "EMMC",
            "f2fs": "EMMC",
            "mtd": "MTD",
            "yaffs2": "MTD",
            "vfat": "EMMC"
        }

    def load_data(self):
        """Load the data from the zips into variables."""
        self.base_ptr = self.load_files(self.base_zip)
        self.input_ptr = self.load_files(self.input_zip)

    def load_files(self, zip_file):
        """Load all the files under /system/ from a ZipFile.

        This is based on the AOSP function `LoadSystemFiles`.

        Args:
            z (ZipFile): ZipFile to load the files from.

        Returns:
            out {filename (str): File object (File)}
                dictionary of the file list + information + data
        """
        out = {}
        extra = self.hooks.extra_files()
        if self.hooks.boot_info():
            extra.append("boot.img")
        for info in zip_file.infolist():
            if (info.filename.startswith("system/") or
                    info.filename in extra) and \
                    not self._is_symlink(info):
                f_name = info.filename
                out[f_name] = self.file_pointer(f_name, zip_file)
        return out

    def get_edify(self, zip_file=None):
        """Get the edify script's content as a string.

        Keyword args:
            zip_file (ZipFile): the edify script to read (input_zip is used if
                this is not provided).
        """
        zip_file = zip_file or self.input_zip
        return zip_file.read(
            "META-INF/com/google/android/updater-script").decode()

    def get_file_from_ptr(self, file_ptr):
        """Produce a file object based on the data in a pointer."""
        zip_file = file_ptr['zip']
        f_name = file_ptr['name']
        data = zip_file.read(f_name)
        ttime = zip_file.getinfo(f_name).date_time
        return self.file_object(f_name, data, ttime)

    def mount_system(self):
        """Generate edify commands for mounting system, and return
        as a list

        Returns:
            (list of str): list of commands for mounting the system
        """
        system_info = self.hooks.system_info()
        if not system_info:
            return []
        system_part = system_info[1]
        system_part_type = self.part_types[system_part]
        system_dev = system_info[0]
        return [self.edify.ui_print("Mounting system..."),
                self.edify.mount(
                    system_part, system_part_type, system_dev, "/system"
                )]

    def create_patches(self, to_diff):
        """Create and zip the patches

        Args:
            to_diff (list of str): list of all the files to be diffed
        """
        counter = 1
        amount = len(to_diff)

        for f_name in to_diff:
            print("patching " + f_name + ": " + str(counter) + " of " + str(amount))

            n_file = self.get_file_from_ptr(self.input_ptr[f_name])
            b_file = self.get_file_from_ptr(self.base_ptr[f_name])
            p_data = self.compute_diff(b_file, n_file)

            patch_path = "patch/" + f_name + ".p"
            p_file = self.file_object(patch_path, p_data, localtime(time()))
            self.add_to_zip(p_file, self.output_zip)

            counter += 1

    def verify_system(self, to_diff):
        """Generate edify commands for verifying system, and return
        as a list

        Args:
            to_diff (list of str): list of all the files to be diffed
        Returns:
            (list of str): List of commands for verifying the system
        """
        script = [self.edify.ui_print("Verifying current system...")]

        for f_name in to_diff:
            if not f_name.startswith("system/"):
                continue  # for now we skip anything non standard

            n_file = self.get_file_from_ptr(self.input_ptr[f_name])
            b_file = self.get_file_from_ptr(self.base_ptr[f_name])

            script.append(self.edify.apply_patch_check("/" + f_name,
                                                       b_file['sha1'],
                                                       n_file['sha1']))
        script.extend(self.assert_boot())
        return script

    def delete_files(self):
        """Generate edify commands for deleting unneeded files

        Returns:
            (list of str): List of commands for removing files
        """
        to_remove = self.find_removes()
        if not to_remove:
            return []
        return [self.edify.ui_print("Removing files..."),
                self.edify.delete(to_remove)]

    def patch_system(self, to_diff):
        """Generate edify commands for patching system, and return
        as a list

        Args:
            to_diff (list of str): list of all the files to be diffed
        Returns:
            (list of str): List of commands for patching the system
        """

        script = [self.edify.ui_print("Patching system files...")]

        for f_name in to_diff:
            if not f_name.startswith("system/"):
                continue  # for now we skip anything non standard

            n_file = self.get_file_from_ptr(self.input_ptr[f_name])
            b_file = self.get_file_from_ptr(self.base_ptr[f_name])

            script.append(self.edify.apply_patch("/" + b_file['name'],
                          "-",
                          n_file['size'],
                          n_file['sha1'],
                          b_file['sha1'],
                          "patch/" + b_file['name'] + ".p"))
        script.extend(self.flash_boot())
        return script

    def unmount_system(self):
        """Generate edify commands for unmounting system, and return
        as a list

        Returns:
            (list of str): list of commands for unmounting the system
        """
        if not self.hooks.system_info():
            return []

        return [self.edify.ui_print("Unmounting system..."),
                self.edify.unmount("/system")]

    def generate(self):
        """Generate the new zip with all the diff files."""
        if not all([self.base_ptr, self.input_ptr]):
            self.load_data()

        to_diff = self.find_diffs()
        self.create_patches(to_diff)

        script = self.mount_system()
        script.extend(self.verify_system(to_diff))
        script.extend(self.hooks.pre_flash_script())
        script.extend(self.patch_system(to_diff))
        script.extend(self.delete_files())
        script.extend(self.hooks.post_flash_script())
        script.extend(self.unmount_system())

        self.add_updater(script)
        self.output_zip.close()

    def assert_boot(self):
        """Generate assert check for the boot image."""
        boot_info = self.hooks.boot_info()
        if not boot_info:
            return []
        part_type = self.part_types[boot_info[1]]
        b_file = self.get_file_from_ptr(self.base_ptr['boot.img'])
        n_file = self.get_file_from_ptr(self.input_ptr['boot.img'])
        b_size = b_file['size']
        n_size = n_file['size']
        b_sha = b_file['sha1']
        n_sha = n_file['sha1']
        return [self.edify.apply_patch_check(
            "%s:%s:%d:%s:%d:%s" % (
                part_type, boot_info[0],
                b_size, b_sha, n_size, n_sha)
        )]

    def flash_boot(self):
        """Generate flash script for the boot image."""
        boot_info = self.hooks.boot_info()
        if not boot_info:
            return []
        part_type = self.part_types[boot_info[1]]
        b_file = self.get_file_from_ptr(self.base_ptr['boot.img'])
        n_file = self.get_file_from_ptr(self.input_ptr['boot.img'])
        b_size = b_file['size']
        n_size = n_file['size']
        b_sha = b_file['sha1']
        n_sha = n_file['sha1']
        return [self.edify.apply_patch(
            "%s:%s:%d:%s:%d:%s" % (
                part_type, boot_info[0],
                b_size, b_sha, n_size, n_sha),
            "-",
            n_size, n_sha, b_sha, "patch/boot.img.p"
        )]

    def add_updater(self, script):
        """Add updater script and binary to the update zip.

        Args:
            script (list): list of the edify commands that constitute the
                updater-script.
        """
        script = '\n'.join(script)
        s_file = {
            'name': "META-INF/com/google/android/updater-script",
            'data': script,
            'time': localtime(time()),
        }
        self.add_to_zip(s_file, self.output_zip)
        ed_bin_name = "META-INF/com/google/android/update-binary"
        ed_bin_info = self.input_zip.getinfo(ed_bin_name)
        ed_bin_data = self.input_zip.read(ed_bin_name)
        ed_bin = self.file_object(ed_bin_name, ed_bin_data,
                                  ed_bin_info.date_time)
        self.add_to_zip(ed_bin, self.output_zip)

    def find_diffs(self):
        """Filter out changed files from the input zip.

        Returns:
            to_diff (list): list of all the files that need a patch.
        """
        to_diff = []
        to_copy = self.hooks.to_copy()
        for f_name in self.input_ptr.keys():
            n_file = self.get_file_from_ptr(self.input_ptr[f_name])
            b_file = self.base_ptr.get(f_name, None)
            if b_file:
                b_file = self.get_file_from_ptr(b_file)

            if b_file is None or f_name in to_copy:
                self.add_to_zip(n_file, self.output_zip)
            elif n_file['sha1'] != b_file['sha1']:
                to_diff.append(f_name)
        return to_diff

    def find_removes(self):
        """Find files to be removed from the system.

        Returns:
            to_remove (list): list of all the files that need removing.
        """
        to_remove = []
        for f_name in self.base_ptr.keys():
            if not self.input_ptr.get(f_name, None):
                to_remove.append(f_name)
        return to_remove

    def compute_diff(self, b_file, n_file):
        """Create the patch.

        Args:
            b_file (dict, see file_object): base file to diff against.
            n_file (dict, see file_object): new file to diff with.

        Returns:
            raw data of the patch file.
        """
        if os_name == "nt":
            if not bs_diff:
                print("ERROR: python bsdiff4 is required for windows")
                exit(1)
            return bs_diff(bytes(b_file['data']), bytes(n_file['data']))

        diff_programs = {
            ".gz": ["imgdiff"],
            ".img": ["imgdiff"],
            ".apk": ["imgdiff", "-z"],
            ".jar": ["imgdiff", "-z"],
            ".zip": ["imgdiff", "-z"],
        }

        ext = path.splitext(b_file['name'])[1]
        cmd = diff_programs.get(ext, ['bsdiff'])

        if cmd == ['bsdiff'] and bs_diff:
            return bs_diff(bytes(b_file['data']), bytes(n_file['data']))

        b_temp = self.write_to_temp(b_file)
        n_temp = self.write_to_temp(n_file)
        p_temp = NamedTemporaryFile()

        cmd.extend([b_temp.name, n_temp.name, p_temp.name])
        out = STDOUT if self.verbose else open(devnull, 'w')
        p = Popen(cmd, stdout=out)
        _, err = p.communicate()
        if err or p.returncode != 0:
            print("WARNING: failure running %s" % cmd)
            return None
        return p_temp.read()

    @staticmethod
    def _is_symlink(info):
        """Check if the ZipInfo object represents a symlink.

        This is the AOSP function `IsSymlink` (adapted for 3.x support).

        Args:
            info (ZipInfo): ZipInfo object of a file in a zip.

        Returns (boolean):
            True if symlink, else False.
        """
        return (info.external_attr >> 16) & 0o770000 == 0o120000

    @staticmethod
    def file_object(name, data, time):
        """Create a file object as a dictionary."""
        return {
            'name': name,
            'data': data,
            'time': time,
            'size': len(data),
            'sha1': sha1(data).hexdigest()
        }

    @staticmethod
    def file_pointer(name, zip_file):
        """Create a file pointer as a dictionary.

        This holds only the name and a pointer to the zip.
        """
        return {
            'name': name,
            'zip': zip_file
        }

    @staticmethod
    def add_to_zip(file_obj, z_file):
        """Add the file to the zip and sets the attributes."""
        zinfo = ZipInfo(file_obj['name'], file_obj['time'])
        zinfo.compress_type = z_file.compression
        zinfo.external_attr = 0o644 << 16
        z_file.writestr(zinfo, file_obj['data'])

    @staticmethod
    def write_to_temp(file_obj, delete=True):
        t = NamedTemporaryFile(delete=delete)
        t.write(file_obj['data'])
        t.flush()
        return t


class FileNotFound(Exception):
    """Error class for handling missing files."""
    def __init__(self, value):
        """
        Args:
            value (str): Location of missing file
        """
        message = " ".join(("File Not Found:", value))
        super(FileNotFound, self).__init__(message)
        self.value = value
        self.message = message

    def __str__(self):
        return repr(self.message)


def cli():
    """Command line interface to build an incremental update."""
    parser = argparse.ArgumentParser(prog=__program__)
    parser.add_argument('-b', action="store", dest="base_zip",
                        required=True, help="Location of the base zip")
    parser.add_argument('-i', action="store", dest="input_zip",
                        required=True, help="Location of the new zip")
    parser.add_argument('-o', action="store", dest="output_zip",
                        required=True, help="Location of the output zip")
    parser.add_argument('-v', action="store_true", dest="verbose",
                        default=False, help="verbose logging")
    parser.add_argument('--version', action='version',
                        version='%(prog)s {}'.format(__version__),
                        help="Output version information")

    options = parser.parse_args()
    dj = DeltaJen(options.base_zip, options.input_zip,
                  options.output_zip, verbose=options.verbose)
    dj.generate()

if __name__ == '__main__':
    from sys import exit as sys_exit, stderr, version_info
    # argparse requires Python2.7 or Python3.2+
    if version_info[0:2] < (2, 7) or \
            (version_info[0] == 3 and
             version_info[1] < 3):

        print("You must use at least Python 2.7 or 3.2 to use the cli "
              "version of DeltaJen", file=stderr)
        sys_exit(1)

    import argparse
    cli()

