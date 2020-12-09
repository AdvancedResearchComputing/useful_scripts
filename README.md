# useful_scripts

This is a place to share useful scripts for ARC systems.  Easy to maintain, allows users to contribute, ...


# Putting this here to save memory space

Basically making this location behave like a module:

1. Clone into /apps (this required SA to create /apps/useful_scripts as CS doesn't have write permissions in the base of /apps): 
cd /apps; git clone git@github.com:AdvancedResearchComputing/useful_scripts.git

2. Change permissions to make sure that everyone can edit going forward:
chgrp -R arc.arcadm /apps/useful_scripts/*

3. Symlink the modulefile so it's in the MODULEPATH (note that the modulefile is also tracked in the git repo): 
ln -s '/apps/useful_scripts/modulefile/useful_scripts.lua' /apps/modulefiles/useful_scripts.lua

4. Add to default modules by editing the DefaultModules modulefile (SA did this)

