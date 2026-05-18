import os
import re
import shutil
from pathlib import Path

# --- CONFIGURATION ---
# Paths relative to the repository root
ALLOWED_PATHS = [
    "src", "test", "migrations", "api", "scripts", 
    "vendor", "supabase", "test-apps",
    "package.json", "tsconfig.json", "CHANGELOG.md", "README.md"
]

EXCLUDED_PATHS = [
    "demo", "packages/server", "agent-network-proxy",
    "CLAUDE.md", ".mcp.json", "docs/internal"
]

# JIRA Project Prefixes to strip (e.g., ABXAGNTS-123, DVO-456)
JIRA_PROJECTS = [
    "ABXAGNTS",
    "DVO"
]

# Words or strings that must be stripped completely if found in text files
CUSTOM_BLOCKED_WORDS = [
    # Add internal URLs, employee names, or secret keywords here later
]

# Target directory where the public repo clone lives inside the runner
PUBLIC_REPO_DIR = Path("./target-public-repo")
INTERNAL_REPO_DIR = Path(".")

# --- DYNAMIC REGEX GENERATION ---
# Joins the prefixes into a pattern like: \b(ABXAGNTS|DVO|INFRA)-\d+\b
if JIRA_PROJECTS:
    joined_projects = "|".join(re.escape(proj) for proj in JIRA_PROJECTS)
    JIRA_REGEX = re.compile(rf'\b({joined_projects})-\d+\b', re.IGNORECASE)
else:
    # Fallback if the list is empty so the script doesn't crash
    JIRA_REGEX = re.compile(r'$^') 

def should_sync(path: Path) -> bool:
    """Determines if a file path is allowed to cross over to the public repo."""
    rel_path = path.relative_to(INTERNAL_REPO_DIR)
    path_str = str(rel_path).replace("\\", "/") # Normalize Windows paths if any

    # 1. Check hardcoded exclusions
    for exc in EXCLUDED_PATHS:
        if path_str == exc or path_str.startswith(exc + "/"):
            return False

    # 2. Check for any file matching *.internal.*
    if ".internal." in path.name:
        return False

    # 3. Check allowed paths
    for allow in ALLOWED_PATHS:
        if path_str == allow or path_str.startswith(allow + "/"):
            return True

    return False

def scrub_content(content: str) -> str:
    """Removes sensitive references and replaces them with a blank string."""
    # Strip JIRA tickets
    content = JIRA_REGEX.sub("", content)
    
    # Strip custom blocked words
    for word in CUSTOM_BLOCKED_WORDS:
        content = content.replace(word, "")
        
    return content

def sync_and_scrub():
    print("Starting sync prep from internal to public directory...")
    
    # Clean out any old files in the public directory paths we manage to handle deleted files properly
    for allowed in ALLOWED_PATHS:
        target_path = PUBLIC_REPO_DIR / allowed
        if target_path.exists():
            if target_path.is_dir():
                shutil.rmtree(target_path)
            else:
                target_path.unlink()

    for root, dirs, files in os.walk(INTERNAL_REPO_DIR):
        # Skip the public target directory and git metadata
        if ".git" in root or "target-public-repo" in root or ".github" in root:
            continue
            
        for file in files:
            source_file = Path(root) / file
            
            if should_sync(source_file):
                rel_path = source_file.relative_to(INTERNAL_REPO_DIR)
                dest_file = PUBLIC_REPO_DIR / rel_path
                
                # Ensure parent directories exist in target
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Check if it's a file type we can safely scrub text within
                # (Prevents corrupting binaries like images/zips if they exist in vendor or assets)
                if file.endswith(('.ts', '.js', '.json', '.md', '.sql', '.sh', '.yml', '.yaml', '.txt')):
                    try:
                        with open(source_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        scrubbed = scrub_content(content)
                        
                        with open(dest_file, 'w', encoding='utf-8') as f:
                            f.write(scrubbed)
                    except Exception as e:
                        print(f"Skipping scrub for {rel_path} due to read error: {e}")
                        shutil.copy2(source_file, dest_file)
                else:
                    # Binary or non-text file, just copy directly
                    shutil.copy2(source_file, dest_file)

    print("Sync prep complete! All allowed files staged and scrubbed.")

if __name__ == "__main__":
    sync_and_scrub()