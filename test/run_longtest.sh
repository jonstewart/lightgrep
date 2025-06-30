for tests in re_gen/*.bz2 ; do
	echo "$tests"
	bzcat $tests | test/test longTest
done
