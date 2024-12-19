# Website

This website is built using [Docusaurus](https://docusaurus.io/), a modern static website generator.

### Installation

```
$ yarn
```

### Local Development

```
$ yarn start
```

This command starts a local development server and opens up a browser window. Most changes are reflected live without having to restart the server.

### Build

```
$ yarn build
```

This command generates static content into the `build` directory and can be served using any static contents hosting service.

### Maintenance Notes

- Always run `npm build` locally first to ensure that the website builds correctly.
- When adding new pages, ensure that the sidebar is updated in `sidebars.ts`.
- Check you links, if you're pointing at an .mdx file, you need to omit the extension in the link.
- Code snippets from the repo are made through the [gen script](./gen-code-refs.sh).
    - When adding new code snippets, ensure that the gen script is updated to include the new file.
- Check out the [Docusaurus documentation](https://docusaurus.io/docs/versioning) versioning information.
