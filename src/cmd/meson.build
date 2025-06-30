src = [
	'hitwriter.cpp',
	'main.cpp',
	'options.cpp',
	'optparser.cpp',
	'reader.cpp',
	'searchcontroller.cpp',
	'util.cpp'
]

boost_dep = dependency(‘boost’, modules : [‘filesystem’, 'program_options', 'system'])

executable('lightgrep',
	sources: src,
	cpp_args: ['-DHAVE_CONFIG_H'],
	link_with: [lg_lib],
	dependencies: [
		boost_dep
	],
	include_directories: [incdir, topdir, sys_include]
)
