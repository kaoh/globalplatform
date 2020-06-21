#!/bin/sh
git tag -d $1
git push --delete origin $1
git push --delete github $1
git tag $1
git push origin $1
git push github $1
