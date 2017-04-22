#! /bin/bash
set -e

pushd .. > /dev/null
python ./setup.py build
popd > /dev/null

for i in ../build/lib.linux-*
do
	export PYTHONPATH=$PYTHONPATH:$i
done

for testFile in test_*.py
do
	python $testFile
done
