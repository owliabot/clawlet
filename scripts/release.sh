#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Clawlet Release Script
# Generates changelog from conventional commits and creates a release
# =============================================================================

VERSION=""
DRY_RUN=false
SKIP_CHANGELOG=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] <version>

Generate changelog and create a release.

Arguments:
  version     Version to release (e.g., 0.2.0, without 'v' prefix)

Options:
  --dry-run           Show what would be done without making changes
  --skip-changelog    Skip changelog generation (use existing CHANGELOG.md)
  -h, --help          Show this help message

Examples:
  $0 0.2.0                    # Release v0.2.0 with auto-generated changelog
  $0 --dry-run 0.2.0          # Preview release without making changes
  $0 --skip-changelog 0.2.0   # Release without updating changelog
EOF
    exit 0
}

log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; exit 1; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-changelog)
            SKIP_CHANGELOG=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        -*)
            log_error "Unknown option: $1"
            ;;
        *)
            VERSION="$1"
            shift
            ;;
    esac
done

[[ -z "$VERSION" ]] && log_error "Version required. Usage: $0 <version>"

# Validate version format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    log_error "Invalid version format: $VERSION (expected: X.Y.Z or X.Y.Z-suffix)"
fi

TAG="v$VERSION"
DATE=$(date +%Y-%m-%d)

# Check we're in the repo root
[[ -f "Cargo.toml" ]] || log_error "Must run from repository root"

# Check for uncommitted changes
if ! git diff --quiet HEAD 2>/dev/null; then
    log_error "Uncommitted changes detected. Commit or stash them first."
fi

# Get the previous tag
PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [[ -z "$PREV_TAG" ]]; then
    log_warn "No previous tag found, generating changelog from all commits"
    COMMIT_RANGE="HEAD"
else
    log_info "Previous tag: $PREV_TAG"
    COMMIT_RANGE="$PREV_TAG..HEAD"
fi

# =============================================================================
# Generate Changelog
# =============================================================================

generate_changelog() {
    local temp_file=$(mktemp)
    
    echo "## [$VERSION] - $DATE" >> "$temp_file"
    echo "" >> "$temp_file"
    
    # Collect commits by type
    declare -A commits
    commits[feat]=""
    commits[fix]=""
    commits[docs]=""
    commits[refactor]=""
    commits[test]=""
    commits[ci]=""
    commits[chore]=""
    commits[other]=""
    
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        
        # Parse conventional commit: type(scope): message
        if [[ "$line" =~ ^([a-z]+)(\([^)]+\))?:\ (.+)$ ]]; then
            type="${BASH_REMATCH[1]}"
            scope="${BASH_REMATCH[2]}"
            message="${BASH_REMATCH[3]}"
            
            # Clean up scope
            scope="${scope#(}"
            scope="${scope%)}"
            
            # Format entry
            if [[ -n "$scope" ]]; then
                entry="- **$scope**: $message"
            else
                entry="- $message"
            fi
            
            # Append to appropriate type
            case "$type" in
                feat|fix|docs|refactor|test|ci|chore)
                    commits[$type]+="$entry"$'\n'
                    ;;
                *)
                    commits[other]+="$entry"$'\n'
                    ;;
            esac
        else
            # Non-conventional commit
            commits[other]+="- $line"$'\n'
        fi
    done < <(git log --pretty=format:"%s" $COMMIT_RANGE)
    
    # Write sections
    local has_content=false
    
    if [[ -n "${commits[feat]}" ]]; then
        echo "### Added" >> "$temp_file"
        echo "${commits[feat]}" >> "$temp_file"
        has_content=true
    fi
    
    if [[ -n "${commits[fix]}" ]]; then
        echo "### Fixed" >> "$temp_file"
        echo "${commits[fix]}" >> "$temp_file"
        has_content=true
    fi
    
    if [[ -n "${commits[refactor]}" ]]; then
        echo "### Changed" >> "$temp_file"
        echo "${commits[refactor]}" >> "$temp_file"
        has_content=true
    fi
    
    if [[ -n "${commits[docs]}" ]]; then
        echo "### Documentation" >> "$temp_file"
        echo "${commits[docs]}" >> "$temp_file"
        has_content=true
    fi
    
    if [[ -n "${commits[test]}" ]]; then
        echo "### Testing" >> "$temp_file"
        echo "${commits[test]}" >> "$temp_file"
        has_content=true
    fi
    
    if [[ -n "${commits[ci]}" ]]; then
        echo "### CI/CD" >> "$temp_file"
        echo "${commits[ci]}" >> "$temp_file"
        has_content=true
    fi
    
    if [[ -n "${commits[chore]}" ]] || [[ -n "${commits[other]}" ]]; then
        echo "### Other" >> "$temp_file"
        [[ -n "${commits[chore]}" ]] && echo "${commits[chore]}" >> "$temp_file"
        [[ -n "${commits[other]}" ]] && echo "${commits[other]}" >> "$temp_file"
        has_content=true
    fi
    
    if ! $has_content; then
        echo "### Changed" >> "$temp_file"
        echo "- No significant changes" >> "$temp_file"
    fi
    
    # Add version link
    if [[ -n "$PREV_TAG" ]]; then
        echo "[$VERSION]: https://github.com/owliabot/clawlet/compare/$PREV_TAG...$TAG" >> "$temp_file"
    else
        echo "[$VERSION]: https://github.com/owliabot/clawlet/releases/tag/$TAG" >> "$temp_file"
    fi
    
    echo "$temp_file"
}

# =============================================================================
# Update CHANGELOG.md
# =============================================================================

update_changelog() {
    local new_section_file="$1"
    
    if [[ ! -f "CHANGELOG.md" ]]; then
        # Create new CHANGELOG.md
        cat > CHANGELOG.md <<EOF
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

$(cat "$new_section_file")
EOF
    else
        # Insert new section after header
        local temp_changelog=$(mktemp)
        local inserted=false
        
        while IFS= read -r line; do
            echo "$line" >> "$temp_changelog"
            
            # Insert after the "adheres to Semantic Versioning" line
            if ! $inserted && [[ "$line" =~ "Semantic Versioning" ]]; then
                echo "" >> "$temp_changelog"
                cat "$new_section_file" >> "$temp_changelog"
                inserted=true
            fi
        done < CHANGELOG.md
        
        mv "$temp_changelog" CHANGELOG.md
    fi
}

# =============================================================================
# Update Cargo.toml versions
# =============================================================================

update_cargo_versions() {
    log_info "Updating Cargo.toml versions to $VERSION..."
    
    # Update workspace version
    sed -i "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" Cargo.toml
    
    # Update each crate's Cargo.toml if they have their own version
    for crate_toml in crates/*/Cargo.toml; do
        if grep -q '^version = ' "$crate_toml" 2>/dev/null; then
            sed -i "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" "$crate_toml"
        fi
    done
}

# =============================================================================
# Main
# =============================================================================

log_info "Preparing release $TAG..."

if $SKIP_CHANGELOG; then
    log_warn "Skipping changelog generation"
else
    log_info "Generating changelog from commits ($COMMIT_RANGE)..."
    NEW_SECTION_FILE=$(generate_changelog)
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Generated changelog section:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat "$NEW_SECTION_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
fi

if $DRY_RUN; then
    log_warn "Dry run - no changes will be made"
    echo ""
    echo "Would perform:"
    echo "  1. Update CHANGELOG.md with new section"
    echo "  2. Update version in Cargo.toml files to $VERSION"
    echo "  3. Commit: 'chore: release $TAG'"
    echo "  4. Create tag: $TAG"
    echo "  5. Push commit and tag"
    exit 0
fi

# Confirm
read -p "Proceed with release $TAG? [y/N] " -n 1 -r
echo
[[ ! $REPLY =~ ^[Yy]$ ]] && exit 1

# Update changelog
if ! $SKIP_CHANGELOG; then
    log_info "Updating CHANGELOG.md..."
    update_changelog "$NEW_SECTION_FILE"
    rm "$NEW_SECTION_FILE"
fi

# Update versions
update_cargo_versions

# Commit
log_info "Committing changes..."
git add -A
git commit -m "chore: release $TAG"

# Tag
log_info "Creating tag $TAG..."
git tag -a "$TAG" -m "Release $TAG"

# Push
log_info "Pushing to origin..."
git push origin main
git push origin "$TAG"

log_success "Release $TAG complete!"
echo ""
echo "GitHub Actions will now build and publish the release."
echo "Monitor at: https://github.com/owliabot/clawlet/actions"
