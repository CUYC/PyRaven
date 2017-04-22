INCDIR = [
	"/usr/include",
	"/usr/local/include",
	"/sw/include", # For Mac OS X
	]
LIBDIR = [
	"/usr/lib",
	"/usr/local/lib",
	"/sw/lib/", # For Mac OS X
	]
LIBS   = ["ssl"]
# Pyrex generates C code for which gcc emits warnings, so suppress them
CFLAGS = ["-Wno-implicit", "-Wno-unused"]

try:
	from Pyrex.Distutils import build_ext
	HAVE_PYREX = True
except ImportError:
	HAVE_PYREX = False
	
def main():
	from distutils.core import Extension, setup
	
	RRVFiles_with_pyrex = ["src/metapaw/__RavenRSAVerify.pyx", "src/metapaw/RSA.c"]
	RRVFiles_without_pyrex = ["src/metapaw/__RavenRSAVerify.c", "src/metapaw/RSA.c"]
	sdist2.pyx_files = [ 'src/metapaw/__RavenRSAVerify.pyx' ]
	
	RavenRSAVerifyExtension_options = {
		'name': 'metapaw.__RavenRSAVerify',
		'include_dirs': INCDIR,
		'library_dirs': LIBDIR,
		'libraries': LIBS,
		'extra_compile_args': CFLAGS,
		}
	
	if HAVE_PYREX:
		RavenRSAVerifyExtension_options['sources'] = RRVFiles_with_pyrex
		commandClass = { 'build_ext': build_ext, }
	else:
		print_pyrex_missing_warning()
		RavenRSAVerifyExtension_options['sources'] = RRVFiles_without_pyrex
		commandClass = {}
	
	commandClass['sdist'] = sdist2
	
	extensionModules = [ Extension(**RavenRSAVerifyExtension_options) ]
	
	setup(
		name = "PyRaven",
		version = "1.0",
		
		description  = "A Raven web application agent library for Python",
		license = "LGPL",
		keywords     = "Raven WAA web application agent python",
		author       = "Tom Huckstep, Richard Smith",
		author_email = "pyraven-devel@metapaw.co.uk",
		url          = "http://www.metapaw.co.uk/projects/pyraven/",
		
		classifiers  = [
		"Topic :: Software Development :: Libraries :: Python Modules",
		"Programming Language :: Python",
		"Intended Audience :: Developers",
		"Development Status :: 5 - Production/Stable",
		"License :: OSI Approved :: GNU Lesser General Public License (LGPL)",
		],
		
		package_dir  = { "" : "src"},
		packages = ["metapaw", "metapaw.Raven", "metapaw.Raven.Handlers"],
		
		ext_modules = extensionModules,
		cmdclass = commandClass,
		)

def print_pyrex_missing_warning():
	def print_warning_line(s):
		print "Warning:", s
	
	print_warning_line('Pyrex not found')
	print_warning_line("Compiling __RavenRSAVerify.c without reading __RavenRSAVerify.pyx")
	print_warning_line("This is OK as long as you don't modify __RavenRSAVerify.pyx")

import distutils.command.sdist
class sdist2(distutils.command.sdist.sdist):
	def run(self):
		if not HAVE_PYREX: raise Exception, "Can't make sdist without Pyrex"
		
		from os import system
		for pyx_file in self.pyx_files:
			command = 'pyrexc %s' % pyx_file
			system(command)
			print(command)
		
		distutils.command.sdist.sdist.run(self)

if __name__ == '__main__': main()
