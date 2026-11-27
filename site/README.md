# Build the documentation site

From the repository root, run `just site-serve` to preview changes with live reload. Run `just site` to build the production site and check links, heading anchors and search metadata. These recipes use Zola 0.23.6 and Python 3.11 or newer.

Write guides in `site/content/`. Give each one a unique title, description and weight. Set `extra.group` to a category from `config.toml` and use `extra.keywords` for searchable service and API names. Link between guides with Zola’s `@/filename.md` syntax.

The landing page and guide directory use templates in `site/templates/`. Artwork, fonts, styles and the guide filter are served from `site/static/`. The GitHub Pages workflow publishes the validated `site/public/` build on changes to the site on `main`.
