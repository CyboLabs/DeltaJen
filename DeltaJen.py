#!/usr/bin/env python
#
# Copyright (C) 2014  Anthony King
# Copyright (C) 2014  CyboLabs
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

"""
Generate an incremental patch to work on all aosp based recoveries.
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

"""
Class Hooks:
    Base class for the DeltaJen Hooks.
    Subclass this if you are using a none standard device that usually
    requires files being changed during a standard flash, or at run time.

    Functions:
        These functions are available for the user to change.
        to_copy:
            This should return a list of files that should not be patched
            and instead just copy the file.
            An example of this is for unified devices, where different
            variants have extra folders that are copied to system based
            on which model the device is.
        extra_files:
            This should return a list of files for files that are not in
            /system or boot.img.
            An example of this is for unified devices, where different
            variants use different kernels.
        pre_flash_script:
            This should return a list of edify commands that need to go
            before applying the patches.
            An example of this is for custom handling of a partition.
        post_flash_script:
            This should return a list of edify commands that need to go
            after applying the patches.
            An example of this is for unified devices, where different
            variants use different files.
        boot_info:
            since the boot parameters can't be easily detected, patching
            the boot image is disabled by default.
            If you would like to patch the boot image, include the
            partition, and it's type in a tuple. for example:
            ('/dev/block/platform/msm_sdcc.1/by-name/boot', 'emmc')
        system_info:
            since the system parameters can't be easily detected, mounting
            the system needs some parameters.
            Include the partition, and it's type in a tuple. for example:
            ('/dev/block/platform/msm_sdcc.1/by-name/system', 'ext4')
        [symlinks:
            This should return a list of tuples in the form of
            ('base file location', ['symlink location 1', 'location 2']).
            An example of this is for custom roms that use busybox.]
    Variables:
        main:
            This is a copy of the DeltaJen class. Through this the
            user can access all variables and functions if needed.
            Refer to the DeltaJen documentation for a list of
            functions and variables
"""


class Hooks(object):
    """
    Hook class for DeltaJen, to accommodate for custom zips.
    """
    def __init__(self, main):
        """
        Initialises the Hook class.
        """
        self.main = main
        self.boot_info_cache = None
        self.system_info_cache = None

    def to_copy(self):
        return []

    def extra_files(self):
        return []

    def pre_flash_script(self):
        return []

    def post_flash_script(self):
        return []

    def boot_info(self):
        if self.boot_info_cache is not None:
            return self.boot_info_cache

        print("WARNING: boot information not supplied.")
        edify = self.main.get_edify()
        if edify.find('assert(package_extract_file("boot.img", ' +
                      '"/tmp/boot.img")') != -1:
            print("BML boot info found")
            pos = edify.find('write_raw_image("/tmp/boot.img"') + 34
            end = edify.find('"),', pos)
            dev = edify[pos:end]
            self.boot_info_cache = (dev, "bml")
        elif edify.find('package_extract_file("boot.img", ' +
                        '"/tmp/boot.img");') != -1:
            print("MTD boot info found")
            pos = edify.find('write_raw_image("/tmp/boot.img"') + 34
            end = edify.find('");', pos)
            dev = edify[pos:end]
            self.boot_info_cache = (dev, "mtd")
        elif edify.find('package_extract_file("boot.img", "') != -1:
            print("EMMC boot info found")
            pos = edify.find('package_extract_file("boot.img"') + 34
            end = edify.find('");', pos)
            dev = edify[pos:end]
            self.boot_info_cache = (dev, "emmc")
        if self.boot_info_cache is None:
            print("WARNING: boot info could not be found.")
            self.boot_info_cache = ()
        return self.boot_info_cache

    def system_info(self):
        if self.system_info_cache is not None:
            return self.system_info_cache
        print("WARNING: system partition information not supplied")

        edify = self.main.get_edify()
        mount = re_search(r'mount\("(\S+)"\s*,\s*' +
                          '"(\S+)"\s*,\s*"(\S+)"\s*,\s*"/system"\);', edify)
        if not mount:
            self.system_info_cache = ()
            print("WARNING: system mount info could not be found.")
        else:
            print("Detected system mount info.")
            part = mount.group(1)
            dev = mount.group(3)
            self.system_info_cache = (dev, part)
        return self.system_info_cache


class Edify(object):
    def apply_patch_check(self, f_name, *sha):
        return 'apply_patch_check("%s"' % f_name + \
               "".join([', "%s"' % (i,) for i in sha]) + \
               ') || abort("\\"%s\\" has unexpected contents.");' % f_name

    def ui_print(self, message):
        return 'ui_print("%s");' % message

    def apply_patch(self, srcfile, tgtfile, tgtsize, tgtsha1, *patchpairs):
        if len(patchpairs) % 2 != 0 or len(patchpairs) == 0:
            raise ValueError("bad patches given to ApplyPatch")
        cmd = 'apply_patch("%s", "%s", %s, %d' % (
            srcfile, tgtfile, tgtsha1, tgtsize)
        for i in range(0, len(patchpairs), 2):
            cmd += ', %s, package_extract_file("%s")' % patchpairs[i:i+2]
        cmd += ');'
        return cmd

    def mount(self, part, part_type, device, mnt_pnt):
        return 'mount("%s", "%s", "%s", "%s");' % (
            part, part_type, device, mnt_pnt)

    def unmount(self, mnt_pnt):
        return 'unmount("%s");' % mnt_pnt


"""
Class DeltaJen:
    Variables:
        base_zip    (ZipFile): Location of the original zip to diff against.
        input_zip   (ZipFile): Location of the new zip to diff with.
        output_zip  (ZipFile): Location of the zip to be generated.
        base_data   (dict): Dict built by `_load_files` to contain the
                            contents of the `base_zip`.
        input_data  (dict): Dict built by `_load_files` to contain the
                            contents of the `input_zip`.

    Functions:
        __init__    : Initialises the DeltaJen class.
        get_edify  : Gets the original edify script from input_zip.
        computer_diffs : Creates the diff objects for all the changed files.
        find_diffs : Filters out changed files from the input zip.
        load_files : Load all the files under /system/ from a ZipFile.
        generate    : Main method for building the new zip and edify script.
        load_data   : Calls `_load_files` for all needed zips.
"""


class DeltaJen(object):
    """
    Generate an incremental update based off two zips.
    """

    def __init__(self, base_zip, input_zip, output_zip,
                 hooks=Hooks, edify=Edify, verbose=False):
        """
        Initialises the DeltaJen class.
        Args:
            base_zip (str): Location of the original zip to diff against.
            input_zip (str): Location of the new zip to diff with.
            output_zip (str): Location of the zip to be generated.

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
        """Loads the data from the zips into variables
        """
        self.base_ptr = self.load_files(self.base_zip)
        self.input_ptr = self.load_files(self.input_zip)

    def load_files(self, zip_file):
        """
        Load all the files under /system/ from a ZipFile.
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
        """
        Gets the original edify script from input_zip.
        Returns:
            contents of the edify file as a string.
        """
        zip_file = zip_file or self.input_zip
        return zip_file.read(
            "META-INF/com/google/android/updater-script").decode()

    def get_file_from_ptr(self, file_ptr):
        """
        produce a file object based on the data in a pointer.
        """
        zip_file = file_ptr['zip']
        f_name = file_ptr['name']
        data = zip_file.read(f_name)
        ttime = zip_file.getinfo(f_name).date_time
        return self.file_object(f_name, data, ttime)

    def generate(self):
        """
        Generates the new zip with all the diff files
        """
        if not all([self.base_ptr, self.input_ptr]):
            self.load_data()
        to_diff = self.find_diffs()
        amount = len(to_diff)
        counter = 1
        script = []
        system_info = self.hooks.system_info()
        system_mnt_pnt = "/system"
        if system_info:
            system_part = system_info[1]
            system_part_type = self.part_types[system_part]
            system_dev = system_info[0]
            script.append(self.edify.ui_print("Mounting system..."))
            script.append(self.edify.mount(
                system_part, system_part_type, system_dev, system_mnt_pnt
            ))

        script.append(self.edify.ui_print("Verifying current system..."))
        for f_name in to_diff:
            print("patching " + f_name + ": " + str(counter) + " of " + str(amount))
            counter += 1
            n_file = self.get_file_from_ptr(self.input_ptr[f_name])
            b_file = self.get_file_from_ptr(self.base_ptr[f_name])
            p_data = self.compute_diff(b_file, n_file)
            patch_path = "patch/" + f_name + ".p"
            p_file = self.file_object(patch_path, p_data, localtime(time()))
            self.add_to_zip(p_file, self.output_zip)

            if not f_name.startswith("system/"):
                continue  # for now we skip anything none standard
            script.append(self.edify.apply_patch_check("/" + f_name,
                                                       b_file['sha1'],
                                                       n_file['sha1']))

        script.extend(self.assert_boot())
        script.extend(self.hooks.pre_flash_script())

        script.append(self.edify.ui_print("Patching system files..."))
        for f_name in to_diff:
            if not f_name.startswith("system/"):
                continue  # for now we skip anything none standard
            n_ptr = self.input_ptr[f_name]
            b_ptr = self.base_ptr[f_name]
            n_file = self.get_file_from_ptr(n_ptr)
            b_file = self.get_file_from_ptr(b_ptr)
            script.append(self.edify.apply_patch("/" + b_file['name'],
                          "-",
                          n_file['size'],
                          n_file['sha1'],
                          b_file['sha1'],
                          "patch/" + b_file['name'] + ".p"))

        script.extend(self.flash_boot())
        script.extend(self.hooks.post_flash_script())

        if system_info:
            script.append(self.edify.unmount(system_mnt_pnt))

        self.add_updater(script)

        self.output_zip.close()

    def assert_boot(self):
        """
        some people may not want to flash a boot image.
        make it easier for them to remove it from the script.
        """
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
        """
        Some people may want to flash a boot image, others
        may want to patch it. Make it easier for them to choose.
        """
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
        """
        Filter out changed files from the input zip.
        Returns:
            to_diff (list): list of all the files that need a patch.
        """
        to_diff = []
        to_ignore = self.hooks.to_copy()
        for f_name in self.input_ptr.keys():
            n_file = self.get_file_from_ptr(self.input_ptr[f_name])
            b_file = self.base_ptr.get(f_name, None)
            if b_file:
                b_file = self.get_file_from_ptr(b_file)

            if b_file is None or f_name in to_ignore:
                self.add_to_zip(n_file, self.output_zip)
            elif n_file['sha1'] != b_file['sha1']:
                to_diff.append(f_name)
        return to_diff

    def find_removes(self):
        """
        Finds files to be removed from the system.
        Returns:
            to_remove (list): list of all the files that need removing.
        """
        to_remove = []
        for f_name in self.base_ptr.keys():
            if not self.input_ptr.get(f_name, None):
                to_remove.append(f_name)
        return to_remove

    def compute_diff(self, b_file, n_file):
        """
        Create the patch
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
        """
        Check if the ZipInfo object represents a symlink.
        This is the AOSP function `IsSymlink` (adapted for 3.x support).
        Args:
            info (ZipInfo): ZipInfo object of a file in a zip.
        Returns (boolean):
            true if symlink, else false.
        """
        return (info.external_attr >> 16) & 0o770000 == 0o120000

    @staticmethod
    def file_object(name, data, time):
        """
        create a file object as a dictionary
        """
        return {
            'name': name,
            'data': data,
            'time': time,
            'size': len(data),
            'sha1': sha1(data).hexdigest()
        }

    @staticmethod
    def file_pointer(name, zip_file):
        """
        Create a file pointer as a dictionary.
        This holds only the name, and a pointer to the zip.
        """
        return {
            'name': name,
            'zip': zip_file
        }

    @staticmethod
    def add_to_zip(file_obj, z_file):
        """
        Adds the file to the zip and sets the attributes
        """
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
    """
    Error class for handling missing files
    """
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


class HookNotSubclassed(Exception):
    """
    Error class for handling Hook not being subclassed
    """
    def __init__(self):
        self.message = "hook is not a subclass of Hook"

    def __str__(self):
        return repr(self.message)


def cli():
    """
    Command line interface to build an incremental update
    """
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

