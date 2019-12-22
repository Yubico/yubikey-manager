# ----------------------------------------------------------------------------
# Copyright (c) 2008 David James
# Copyright (c) 2006-2008 Alex Holkner
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of pyglet nor the names of its
#    contributors may be used to endorse or promote products
#    derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ----------------------------------------------------------------------------

from __future__ import absolute_import

import os.path
import re
import sys
import glob
import platform
import ctypes
import ctypes.util


def _environ_path(name):
    if name in os.environ:
        return os.environ[name].split(':')
    else:
        return []


class LibraryLoader(object):

    def __init__(self):
        self.other_dirs = []

    def load_library(self, libname, version=None, extra_paths=[]):
        """Given the name of a library, load it."""

        paths = self.getpaths(libname, extra_paths)

        for path in paths:
            if os.path.exists(path):
                return self.load(path)

        raise ImportError('%s not found.' % libname)

    def load(self, path):
        """Given a path to a library, load it."""
        try:
            # Darwin requires dlopen to be called with mode RTLD_GLOBAL instead
            # of the default RTLD_LOCAL.  Without this, you end up with
            # libraries not being loadable, resulting in "Symbol not found"
            # errors
            if sys.platform == 'darwin':
                return ctypes.CDLL(path, ctypes.RTLD_GLOBAL)
            else:
                return ctypes.cdll.LoadLibrary(path)
        except OSError as e:
            raise ImportError(e)

    def getpaths(self, libname, extra_paths):
        """Return a list of paths where the library might be found."""
        if os.path.isabs(libname):
            yield libname
        else:
            for path in self.getplatformpaths(libname, extra_paths):
                yield path

            path = ctypes.util.find_library(libname)
            if path:
                yield path

    def getplatformpaths(self, libname, extra_paths):
        return []

# Darwin (Mac OS X)


class DarwinLibraryLoader(LibraryLoader):
    name_formats = ['lib%s.dylib', 'lib%s.so', 'lib%s.bundle', '%s.dylib',
                    '%s.so', '%s.bundle', '%s']

    def getplatformpaths(self, libname, extra_paths):
        if os.path.pathsep in libname:
            names = [libname]
        else:
            names = [format % libname for format in self.name_formats]

        for dir in extra_paths + self.getdirs(libname):
            for name in names:
                yield os.path.join(dir, name)

    def getdirs(self, libname):
        '''Implements the dylib search as specified in Apple documentation:

        http://developer.apple.com/documentation/DeveloperTools/Conceptual/
            DynamicLibraries/Articles/DynamicLibraryUsageGuidelines.html

        Before commencing the standard search, the method first checks
        the bundle's ``Frameworks`` directory if the application is running
        within a bundle (OS X .app).
        '''

        dyld_fallback_library_path = _environ_path(
            'DYLD_FALLBACK_LIBRARY_PATH')
        if not dyld_fallback_library_path:
            dyld_fallback_library_path = [os.path.expanduser('~/lib'),
                                          '/usr/local/lib', '/usr/lib']

        dirs = []

        if '/' in libname:
            dirs.extend(_environ_path('DYLD_LIBRARY_PATH'))
        else:
            dirs.extend(_environ_path('LD_LIBRARY_PATH'))
            dirs.extend(_environ_path('DYLD_LIBRARY_PATH'))

        dirs.extend(self.other_dirs)
        dirs.append('.')
        dirs.append(os.path.dirname(__file__))

        if hasattr(sys, 'frozen') and sys.frozen == 'macosx_app':
            dirs.append(os.path.join(
                os.environ['RESOURCEPATH'],
                '..',
                'Frameworks'))

        if hasattr(sys, 'frozen'):
            dirs.append(sys._MEIPASS)

        dirs.append(
            os.path.join(os.path.dirname(sys.executable), '../Frameworks'))

        dirs.extend(dyld_fallback_library_path)

        return dirs

# Posix


class PosixLibraryLoader(LibraryLoader):
    _ld_so_cache = None

    def load_library(self, libname, version=None, extra_paths=[]):
        for dir in extra_paths:  # Favor extra_paths
            for path in glob.glob('%s/lib%s*.s[ol]*' % (dir, libname)):
                return self.load(path)

        try:
            found = ctypes.util.find_library(libname)
            if found is not None:
                return self.load(found)
        except ImportError:
            pass
        return super(PosixLibraryLoader, self).load_library(
            libname, version, extra_paths)

    def _create_ld_so_cache(self):
        # Recreate search path followed by ld.so.  This is going to be
        # slow to build, and incorrect (ld.so uses ld.so.cache, which may
        # not be up-to-date).  Used only as fallback for distros without
        # /sbin/ldconfig.
        #
        # We assume the DT_RPATH and DT_RUNPATH binary sections are omitted.

        directories = []
        for name in ('LD_LIBRARY_PATH',
                     'SHLIB_PATH',  # HPUX
                     'LIBPATH',  # OS/2, AIX
                     'LIBRARY_PATH',  # BE/OS
                     ):
            if name in os.environ:
                directories.extend(os.environ[name].split(os.pathsep))
        directories.extend(self.other_dirs)
        directories.append('.')
        directories.append(os.path.dirname(__file__))

        try:
            directories.extend([dir.strip()
                               for dir in open('/etc/ld.so.conf')])
        except IOError:
            pass

        unix_lib_dirs_list = ['/lib', '/usr/lib', '/lib64', '/usr/lib64']
        if sys.platform.startswith('linux'):
            # Try and support multiarch work in Ubuntu
            # https://wiki.ubuntu.com/MultiarchSpec
            bitage = platform.architecture()[0]
            if bitage.startswith('32'):
                # Assume Intel/AMD x86 compat
                unix_lib_dirs_list += [
                    '/lib/i386-linux-gnu', '/usr/lib/i386-linux-gnu']
            elif bitage.startswith('64'):
                # Assume Intel/AMD x86 compat
                unix_lib_dirs_list += [
                    '/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu']
            else:
                # guess...
                unix_lib_dirs_list += glob.glob('/lib/*linux-gnu')
        directories.extend(unix_lib_dirs_list)

        cache = {}
        lib_re = re.compile(r'lib(.*)\.s[ol]')
        for dir in directories:
            try:
                for path in glob.glob('%s/*.s[ol]*' % dir):
                    file = os.path.basename(path)

                    # Index by filename
                    if file not in cache:
                        cache[file] = path

                    # Index by library name
                    match = lib_re.match(file)
                    if match:
                        library = match.group(1)
                        if library not in cache:
                            cache[library] = path
            except OSError:
                pass

        self._ld_so_cache = cache

    def getplatformpaths(self, libname, extra_paths):
        if self._ld_so_cache is None:
            self._create_ld_so_cache()

        for dir in extra_paths:
            for path in glob.glob('%s/lib%s*.s[ol]*' % (dir, libname)):
                yield path

        result = self._ld_so_cache.get(libname)
        if result:
            yield result

        path = ctypes.util.find_library(libname)
        if path:
            yield os.path.join('/lib', path)

# Windows


class _WindowsLibrary(object):

    def __init__(self, path):
        # If the DLL loads additional DLLs we need to be in the correct dir
        cwd = os.getcwd()
        dir = os.path.dirname(path)
        try:
            if dir:
                os.chdir(dir)
            self.cdll = ctypes.cdll.LoadLibrary(path)
            self.windll = ctypes.windll.LoadLibrary(path)
        finally:
            if dir:
                os.chdir(cwd)

    def __getattr__(self, name):
        try:
            return getattr(self.cdll, name)
        except AttributeError:
            try:
                return getattr(self.windll, name)
            except AttributeError:
                raise


class WindowsLibraryLoader(LibraryLoader):
    name_formats = ['lib%s*.dll']

    def load_library(self, libname, version=None, extra_paths=[]):
        tmp = os.environ['PATH']
        try:
            os.environ['PATH'] = ''
            result = LibraryLoader.load_library(self, libname, version,
                                                extra_paths)
        except ImportError:
            result = None
            if os.path.sep not in libname:
                formats = self.name_formats[:]
                if version:
                    formats.append('lib%%s-%s.dll' % version)
                for name in formats:
                    try:
                        result = getattr(ctypes.cdll, name % libname)
                        if result:
                            break
                    except WindowsError:
                        result = None
            if result is None:
                try:
                    result = getattr(ctypes.cdll, libname)
                except WindowsError:
                    result = None
            if result is None:
                raise ImportError('%s not found.' % libname)
        finally:
            os.environ['PATH'] = tmp
        return result

    def load(self, path):
        return _WindowsLibrary(path)

    def getplatformpaths(self, libname, extra_paths):
        if os.path.sep not in libname:
            for name in self.name_formats:
                for dir in extra_paths:
                    pattern = os.path.abspath(os.path.join(dir, name % libname))
                    for path in glob.glob(pattern):
                        yield path
                path = ctypes.util.find_library(name % libname)
                if path:
                    yield path

# Platform switching

# If your value of sys.platform does not appear in this dict, please contact
# the Ctypesgen maintainers.


loaderclass = {
    'darwin':   DarwinLibraryLoader,
    'cygwin':   WindowsLibraryLoader,
    'win32':    WindowsLibraryLoader
}


loader = loaderclass.get(sys.platform, PosixLibraryLoader)()


def add_library_search_dirs(other_dirs):
    loader.other_dirs = other_dirs


load_library = loader.load_library

del loaderclass
