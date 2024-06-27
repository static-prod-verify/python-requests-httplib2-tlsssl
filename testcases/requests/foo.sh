#!/bin/bash

for L in `find . -maxdepth 1 -name '*0*'`
do
	cd $L
	mkdir binary
	cd source
	zip ../binary/python-app.pya ./*
	cd ../../	
done
