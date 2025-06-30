project('lightgrep',
		'cpp',
		default_options: ['cpp_std=c++17']
)

incdir = include_directories('include')
topdir = include_directories('.') # for config.h :eyeroll:
sys_include = include_directories('/opt/local/include', is_system: true)

subdir('src')
