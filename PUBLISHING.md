# Publish the source on GitHub

The source tree is ready to publish; this archive is not itself a GitHub
repository. A repository URL and a license choice belong to its owner.

1. Choose a license before making the repository public; see
   [GitHub's licensing guide](https://docs.github.com/articles/licensing-a-repository).
   A public repository
   without a license can be viewed and cloned, but it does not grant others
   general rights to reuse or modify the code. Add the chosen `LICENSE` file
   with the correct copyright owner. If your intent is a commercial source
   available product, choose those terms deliberately instead of assuming a
   permissive open-source license.
2. Create an empty GitHub repository in the intended owner account. Do not
   initialize it with a conflicting README or `.gitignore`.
3. From this directory, inspect what will be committed, then push to the
   repository URL supplied by GitHub:

```bash
git init -b main
git add .
git status --short
git commit -m "Initial ThreatResearch MCP release"
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
```

The `.gitignore` excludes credentials, database files, generated lab output,
virtual environments, and binary wheels. The committed
`examples/soc_lab/sample_report.json` contains fictional cases and a relative
watch command. GitHub Actions CI tests the package and MCP stdio tool call
without SIEM credentials or live feed requests.

After CI succeeds, users can clone the repository and follow
[QUICKSTART.md](QUICKSTART.md). Each organization creates its **own** pack;
assets, tokens, and incident data stay outside the repository. Distribute a
wheel through a GitHub Release if desired, built from the tagged source.
