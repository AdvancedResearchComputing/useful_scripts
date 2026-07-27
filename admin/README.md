## Admin: deploying updates/changes for `useful_scripts`

This README explains how the deploy_useful_scripts helps keep `/apps/common/useful_scripts` in sync with the GitHub repository.

The deploy_useful_scripts script:

- Copies only your specific changes/updates  from the repo into `/apps/common/useful_scripts`
- Preserves the permissions
- Skips utilities files whose contents have not changed

---

### 1. Layout (example)

Recommended structure:

- Repository clone (example):  
  `~/arc_repos/useful_scripts_repo`

- Live scripts on the cluster:  
  `/apps/common/useful_scripts`

- Deploy script inside the repo:  
  `admin/deploy_useful_scripts.sh`

The deploy script automatically detects the repository root based on its own location. The clone path can be different as long as the `admin/` directory stays inside the repository.

---

### 2. One time setup per admin

Run these commands once in your home directory to set up your local clone and deploy script.

```bash
mkdir -p ~/arc_repos
cd ~/arc_repos

# Clone the GitHub repo
git clone https://github.com/AdvancedResearchComputing/useful_scripts.git useful_scripts_repo

cd useful_scripts_repo

# Make the deploy script executable
chmod +x admin/deploy_useful_scripts.sh

```
--- 


### 3. Deploying changes  (just 3 steps)


From your home directory:
```bash
cd ~/arc_repos/useful_scripts_repo

# Get latest changes from GitHub (main branch)
git pull

# Deploy to /apps/common/useful_scripts
./admin/deploy_useful_scripts.sh

```

