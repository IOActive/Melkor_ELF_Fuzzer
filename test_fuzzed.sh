#!/bin/sh

if [ $# -lt 1 ]; then
	echo "Usage: $0 [options] <dir_with_malformed_ELFs_aka_orcs> [program_and_parameters] > OUT.txt (includes stdout and stderr)"
	echo "	[options]:"
	echo "		-B Fuzz \$LD_BIND_NOW     (fuzzing rule env1)"
	echo "		-L Fuzz \$LD_LIBRARY_PATH (fuzzing rule env2)"
	echo "		-P Fuzz \$LD_PRELOAD      (fuzzing rule env3)"
	echo ""
	echo "	[program_and_parameters]:"
	echo "		If no program given, the malformed ELF will be executed ./orc (OS' ELF loader testing)"
	echo ""
	echo "Examples:"
	echo "$0 orcs_foo/"
	echo "$0 -BL orcs_foo/ > EXECUTION_FOO_WITH_FUZZED_LD.txt"
	echo "$0 orcs_libfoo.so/ \"readelf -SW\""
	echo "$0 -P orcs_foo/"
	echo "$0 orcs_foo_standalone/ \"readelf -S\" > READELF_FUZZING_RESULTS.txt"
	echo "$0 orcs_foo.o/ \"gcc -o foo\""
	echo "$0 -L orcs_foo_static/ \"gdb -q\""
	echo ""
	exit 0
else
	while getopts LPB option; do
		case "${option}" in
			B) LD_BIND_NOW_FUZZ=1;;
			L) LD_LIBRARY_PATH_FUZZ=1;;
			P) LD_PRELOAD_FUZZ=1;;
			*) exit;;
		esac
	done

	if [ $LD_BIND_NOW_FUZZ ] || [ $LD_LIBRARY_PATH_FUZZ ] || [ $LD_PRELOAD_FUZZ ]; then
		shift $(( OPTIND - 1 ));
	fi

	echo ""
	echo "==================================================="
	echo ""

	if [ $LD_BIND_NOW_FUZZ ]; then
		echo -n "Exporting fuzzed \$LD_BIND_NOW ... "
		export LD_BIND_NOW=`src/env1`
		echo "DONE"
	fi

	if [ $LD_LIBRARY_PATH_FUZZ ]; then
		echo -n "Exporting fuzzed \$LD_LIBRARY_PATH ... "
		export LD_LIBRARY_PATH=`src/env2`
		echo "DONE"
	fi

	if [ $LD_PRELOAD_FUZZ ]; then
		echo -n "\$LD_PRELOAD will change on every test ... "
	fi

	echo ""
	echo "==================================================="
	echo ""
	echo "LD_* vars in environment:"
	echo ""
	src/print_envp_vars 2>/dev/null # stderr sent to null to avoid the error in case LD_PRELOAD is fuzzed as well
	echo "==================================================="

	echo ""
	echo "Press any key to start the testing... "
	read x

	if [ -d $1 ]; then
		for file in $(ls $1 | egrep -v "Report"); do
			echo "---------------------------------------------------"

			if [ "$2" ]; then
				echo "Testing program: $2 $1$file"
				if [ $LD_PRELOAD_FUZZ ]; then
					LD_PRELOAD=`src/env3` $2 $1$file 2>&1
					#echo quit | LD_PRELOAD=`src/env3` $2 $1$file 2>&1 # Example: "echo quit | gdb -q orcs/x"
				else
					$2 $1$file 2>&1
					#echo quit | $2 $1$file 2>&1 # Example: "echo quit | gdb -q orcs/x"
				fi
			else
				echo "Testing binary: $1$file"
				if [ $LD_PRELOAD_FUZZ ]; then
					LD_PRELOAD=`src/env3` $1$file 2>&1
				else
					$1$file 2>&1
				fi
			fi
		done
	else
		echo "$1 doesn't exist or is not a directory !"
		exit 1;
	fi
fi
