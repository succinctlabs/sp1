import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'SP1 Docs',
  tagline: 'Prove the worlds software.',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://docs.succinct.xyz',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'succinctlabs', // Usually your GitHub org/user name.
  projectName: 'sp1', // Usually your repo name.
  deploymentBranch: 'dev',
  trailingSlash: false,

  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'throw',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      "classic",
      ({
        docs: {
          sidebarPath: require.resolve("./sidebars.ts"),
        },
        blog: false,
        pages: {},
        theme: {
          customCss: require.resolve("./src/css/custom.css"),
        },
      }),
    ],
  ],

  themeConfig: {
    algolia: {
      apiKey: "8bfb4b393679faa73e8362e3966be8c3", // Public api key
      appId: "P3LCHD8MFM",
      indexName: "succinct",
      searchPagePath: "search",

      // Leaving at the default of `true` for now
      contextualSearch: true,
    },
    docs: {
      sidebar: {
        hideable: false,
      }
    },
    navbar: {
      title: 'SP1 Docs',
      logo: {
        alt: 'Succinct Logo',
        src: 'img/favicon.ico',
      },
      items: [
        {
          href: 'https://github.com/succinctlabs/sp1',
          label: 'GitHub',
          position: 'right',
        },
        {
          type: "docsVersionDropdown",
          position: "right",
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Home',
              to: '/',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'X',
              href: 'https://x.com/succinctlabs',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'Website',
              href: 'https://succinct.xyz',
            },
          ],
        },
      ],
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
    colorMode: {
      defaultMode: 'dark',
    }
  } satisfies Preset.ThemeConfig,
};

export default config;
