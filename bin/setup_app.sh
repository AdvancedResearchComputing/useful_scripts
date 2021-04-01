#!/bin/bash
#Script for ARC personnel to set up a directory and 
#modulefile for a custom software installation

appbase="/apps/packages"
modbase="/apps/modulefiles"

#e.g., tinkercliffs-rome
sysdir=$( basename $EASYBUILD_INSTALLPATH_MODULES )

if [ ! $# -eq 2 ]; then
  echo "setup_app.sh: Setup directory/modulefile for custom software installation"
  echo "Usage: script.sh package version"
  echo "Example: script.sh R 4.0.2-foss-2020a"
  exit 1
else
  app="$1"
  ver="$2"
  appdir="${appbase}/${sysdir}/${app}/${ver}"
  moddir="${modbase}/${sysdir}/${app}"
  modfl="${moddir}/${ver}.lua"

  read -p "Create directories $appdir and $moddir? " -n 1 -r
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo
    mkdir -p $appdir
    mkdir -p $moddir

    cat >$modfl <<EOF
whatis("Name: $app")
whatis("Version: $ver")
whatis("Description: SOFTWAREDESCRIPTION")
whatis("URL: SOFTWAREURL")
 
help([[
SOFTWAREDESCRIPTION
 
Define Environment Variables:
 
    \$EBROOTSOFTWARE - root
      \$SOFTWARE_DIR - root
      \$SOFTWARE_BIN - binaries
      \$SOFTWARE_INC - includes
      \$SOFTWARE_LIB - libraries
    \$SOFTWARE_LIB64 - libraries
 
Prepend Environment Variables:
 
               PATH += \$SOFTWARE_BIN
            MANPATH += \$SOFTWARE_DIR/share/man
            INCLUDE += \$SOFTWARE_INC
    LD_LIBRARY_PATH += \$SOFTWARE_LIB
    LD_LIBRARY_PATH += \$SOFTWARE_LIB64
]])
 
setenv("EBROOTSOFTWARE", "$appdir")
setenv("SOFTWARE_DIR", "$appdir")
setenv("SOFTWARE_BIN", "$appdir/bin")
setenv("SOFTWARE_INC", "$appdir/include")
setenv("SOFTWARE_LIB", "$appdir/lib64")

prepend_path("PATH", "$appdir/bin")
prepend_path("MANPATH", "$appdir/share/man")
prepend_path("INCLUDE", "$appdir/include")
prepend_path("LD_LIBRARY_PATH", "$appdir/lib")
prepend_path("LD_LIBRARY_PATH", "$appdir/lib64")
 
load("foss/2020b")
EOF

  echo "Done. To finish your build:"
  echo " 1. Install your app in $appdir/"
  echo "    - Document the installation so we know how you did it"
  echo " 2. Edit the modulefile in $modfl"
  echo "    - Replace SOFTWARE"
  echo "    - Edit paths"
  echo "    - Set or remove modules to load"

  fi
fi
