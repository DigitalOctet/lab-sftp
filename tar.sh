#!/bin/bash

tar cvf lab4.tar \
 --exclude=../lab-sftp/.* \
 --exclude=../lab-sftp/checkpoint/README.md \
 --exclude=../lab-sftp/tar.sh \
 --exclude=../lab-sftp/build \
 ../lab-sftp