# opcua-kit website

The landing page and documentation build with Zola 0.23.6. From the source checkout’s `site/` directory, run `zola serve` and open the local address it prints. To generate the production site and check its Markdown links, rendered navigation and search metadata, run the following commands.

```sh
zola check --skip-external-links
zola build
python3 check_output.py
```

Edit guides in `content/`. Each guide has a title, a description, a unique weight for ordering, an `extra.group` from `config.toml` and `extra.keywords` for searchable API names. The documentation index, filter and sidebar use that metadata. Link to guides with Zola’s `@/filename.md` syntax so links work under the repository base path.

The landing layout lives in `templates/index.html`. Shared navigation and search metadata live in `templates/base.html`. The styles, font and artwork are served locally from `static/`.

The output checker uses Python 3.11 or newer. The build writes to `public/`. Select **GitHub Actions** as the repository’s Pages source. The **Site** workflow checks pull requests and deploys validated site changes on `main`. Run it manually on `main` to redeploy.
