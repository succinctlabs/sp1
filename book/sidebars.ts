import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */
const sidebars: SidebarsConfig = {
  docs: [
    "introduction",
    "why-use-sp1",
    "what-is-a-zkvm",
    {
      type: "category",
      label: "Getting Started",
      items: [
        "getting-started/install",
        "getting-started/quickstart",
        "getting-started/project-template",
        "getting-started/hardware-requirements",
      ],
      collapsed: false,
    },
    {
      type: "category",
      label: "Writing Programs",
      items: [
        "writing-programs/basics",
        "writing-programs/setup",
        "writing-programs/compiling",
        "writing-programs/inputs-and-outputs",
        "writing-programs/patched-crates",
        "writing-programs/precompiles",
        "writing-programs/proof-aggregation",
        "writing-programs/cycle-tracking",
      ],
      collapsed: false,
    },
    {
      type: "category",
      label: "Proving",
      items: [
        "generating-proofs/basics",
        "generating-proofs/setup",
        "generating-proofs/proof-types",
        "generating-proofs/recommended-workflow",
        {
          type: "category",
          label: "Hardware Acceleration",
          link: { type: "doc", id: "generating-proofs/hardware-acceleration" },
          items: [
            "generating-proofs/hardware-acceleration",
            "generating-proofs/hardware-acceleration/avx",
            "generating-proofs/hardware-acceleration/cuda",
          ],
        },
        {
          type: "category",
          label: "Prover Network",
          link: { type: "doc", id: "generating-proofs/prover-network" },
          items: [
            "generating-proofs/prover-network/key-setup",
            "generating-proofs/prover-network/usage",
            "generating-proofs/prover-network/versions",
          ],
        },
        "generating-proofs/advanced",
      ],
      collapsed: false,
    },
    {
      type: "category",
      label: "Verification",
      items: [
        "verification/off-chain-verification",
        {
          type: "category",
          label: "On-Chain Verification",
          items: [
            "verification/onchain/getting-started",
            "verification/onchain/contract-addresses",
            "verification/onchain/solidity-sdk",
          ],
        },
      ],
      collapsed: false,
    },
    {
      type: "category",
      label: "Troubleshooting & CI",
      items: [
        "developers/common-issues",
        "developers/usage-in-ci",
      ],
      collapsed: false,
    },
    {
      type: "category",
      label: "Security",
      items: [
        "security/security-model",
        "security/rv32im-implementation",
        "security/safe-precompile-usage",
        {
          type: "link",
          label: "Security Policy",
          href: "https://github.com/succinctlabs/sp1/security/policy",
        },
        {
          type: "link",
          label: "Security Advisories",
          href: "https://github.com/succinctlabs/sp1/security/advisories",
        },
        {
          type: "link",
          label: "Audit Reports",
          href: "https://github.com/succinctlabs/sp1/tree/dev/audits",
        },
        {
          type: "link",
          label: "Bug Bounty",
          href: "https://code4rena.com/bounties/succinct",
        },
      ],
    },
  ],
};

export default sidebars;
