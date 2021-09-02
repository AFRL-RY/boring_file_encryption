# Introduction to Boring File Encryption

Encryption Wizard is end of life, DISA is not funding it so AFRL/RI is
going to retire TENS. So what open source tools exist that are FIPS
140-2 approved that we can use for Encryption?  Many years ago NIST
approved OpenSSL but that has not been updated.  No worries Google
forked OpenSSL and created BoringSSL which has been approved by NIST
as FIPS 140-2 approved library:
    https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3318.pdf

Unfortunately Google did not include a program to perform file
encryption so we have created bfe (boring file encryption) program
that will encrypt or decrypt files only using the NIST FIPS 140-2
certified encryption algorithms from the BoringSSL library.  Boring
File Encryption (bfe) is a simple C program which essentially drives 
the BoringSSL library.  bfe handles command line arguments with getopt
which is a standard library for Linux.  This project maintains a clear
delineation between bfe and BoringSSL in order to maintain the FIPS
140-2 certification.

In the PDF above a very specific version of BoringSSL has been NIST
FIPS 140-2 certified for that reason the BoringSSL library code is
kept separately from the bfe driver program and they each have to
be built individually.

This software is designed/tested to work on Ubuntu 20.04 only, in the 
future we might support a Windows version.  A Docker file has been 
included to demonstrate the required dependencies. You can either 
build the software in the Docker container itself or install the 
required dependencies on your Ubuntu 20.04 system.

This software has been approved for use on Defense Research and
Engineering Network (DREN) by AFRL/RY.

## Installing Boring File Encryption

GitHub/GitLab includes a "releases" link which includes a .deb file that
is automatically built when changes are made to the repository.  To 
install bfe first download the latest .deb file from the releases section.
Then use the command:

```bash
sudo dpkg -i bfe_1.2_amd64.deb
```

Change the version number 1.2 as needed for your installation. bfe will
be installed in /usr/local/bin/bfe.

## Building BoringSSL

The instructions below are a summary of the instructions provided by 
NIST:
https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3318.pdf

See page 19.

### Download the BoringSSL library

    curl -o boringssl.tar.xz https://commondatastorage.googleapis.com/chromium-boringssl-docs/fips/boringssl-66005f41fbc3529ffe8d007708756720529da20d.tar.xz


To extract use the command:

```bash
tar xf boringssl.tar.xz
```

### Build the BoringSSL library

Use a printf command to set clang as the compiler:

```
printf "set(CMAKE_C_COMPILER \"clang\")\nset(CMAKE_CXX_COMPILER \"clang++\")\n" > ${HOME}/toolchain
```

With Ubuntu 20.04 clang will error on compile for a "implicit fall-through", so we must turn this off:

```
sed -i '/set(C_CXX_FLAGS "${C_CXX_FLAGS} -Wimplicit-fallthrough")/s/^/#/' CMakeLists.txt
```

We recommend building with static library to insure that FIPS 140-2 
of the Boring SSL library is used:

```
mkdir build && cd build && cmake -GNinja -DCMAKE_TOOLCHAIN_FILE=${HOME}/toolchain -DFIPS=1 -DCMAKE_BUILD_TYPE=Release ..
```

For completeness the command to build with shared libraries is:

```
mkdir build && cd build && cmake -GNinja -DCMAKE_TOOLCHAIN_FILE=${HOME}/toolchain -DFIPS=1 -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=1 ..
```

Finally build BoringSSL and run the tests:

```
ninja
ninja run_tests
```

The module's status can be verified using the following command:

```
./tool/bssl isfips
```

The module will print “1” if it is in a FIPS 140-2 validated mode of 
operation.


## Building the Boring File Encryption driver program

After the BoringSSL library is built next we have to build and test 
the Boring File Encryption (bfe):

```
mkdir build
cd build
cmake ..
make
make test
```

If all the tests pass 100% then you are good to go!

## Using Boring File Encryption

bfe is designed to be used at the command line just like any other
Linux command line program. Use the command:

```
./build/bfe
```

To see the options, most of them are self explanatory. See CMakeLists.txt
for examples.  At one point bfe could use input from redirected stdin and
output from redirected stdout but that would produce testing errors when
bfe was used in a container so this functionality was removed. 


## License

See LICENSE.md.

Boring File Encryption (bfe) is a work of the United States Government. It 
is in the public domain and open source. There is no copyright. You are free
to do anything you want with this source but we like to get credit for our work
and we would like you to offer your changes so we can possibly add them
to the "official" version. Please see CONTRIBUTING.md for information on
how you can contribute to the project.

## References 

- argument parsing in C https://azrael.digipen.edu/~mmead/www/Courses/CS180/getopt.html
- function pointers: https://en.wikipedia.org/wiki/Function_pointer
- determine if stdin is a pipe or terminal https://stackoverflow.com/questions/1312922/detect-if-stdin-is-a-terminal-or-
- How to create .deb Packages for Debian, Ubuntu, and Linux Mint see description https://www.youtube.com/watch?v=ep88vVfzDAo&t=369s
- Debian Packaging Intro https://wiki.debian.org/Packaging/Intro?action=show&redirect=IntroDebianPackaging

## To Do

- [X] Switch to static build
- [X] Create a test a gigabyte file
- [ ] Make better output during encryption/decryption
- [X] Make sure all memory is freed
- [X] When bfe runs with no arguments have it spit out the help information
- [X] Finish README.md
    - [X] Document build process, confirm said process is working
- [X] Default to 256 bits of AES encryption but then the password has to be 32 characters? We have to fix 32 character passwords
- [X] make sure program can work with pipes for tar and gzip
- [X] check file open for Pete's sake
- [ ] Why is BoringSSL tests passing then failing right after?  When we run ninja run_tests on Ubuntu 20.04?
- [ ] Should we have a debug option?

## TVR Notes

### Run specific test

Use the following commands to run a specific named test:

```
ctest -R '^encrypt$'
ctest -R '^decrypt$'
```

### GitLab CI/CD

This project uses the shell executor on GitLab runner with Docker to build and test bfe: 

https://docs.gitlab.com/ee/ci/docker/using_docker_build.html#use-the-shell-executor

It looks like to get the most flexibility we should install a shell runner and then we can run docker
commands on the system with gitlab-runner. 

### How to tag and create a release

```
git tag -a v1.2 -m "version 1.2--creates a .deb binary package and saves as artifact"
git tag
git show v1.2
git push origin v1.2
```

- Create the release as you normally would do with the tag
- Go to pipelines and select the latest build output, click on keep to keep the artifacts.
- Browse the artifacts and copy the link to the deb file
- At the bottom of the release page add a link to the deb file artifact, select it as a package, use the file name as the link title
