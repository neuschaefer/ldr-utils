#!/bin/sh
svn info ${0%/*} | sed -n '/^Last Changed Rev/s|^.*: |svn-|p'
