#!/bin/sh
if [ -d .svn ] ; then
	scm=svn
	ver=$(svn info ${0%/*} | sed -n '/^Last Changed Rev/s|^.*: ||p')
elif [ -d .git ] ; then
	if git config svn-remote.svn.url >/dev/null ; then
		scm=svn
		ver=$(git svn info ${0%/*} | sed -n '/^Last Changed Rev/s|^.*: ||p')
	else
		scm=git
		ver=$(git rev-parse --short --verify HEAD)
	fi
else
	scm=idk
	ver=IDK
fi

printf "%s-%s" "${scm}" "${ver}"
