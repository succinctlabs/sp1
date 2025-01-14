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
    {
      type: "category",
      label: "Getting Started",
      items: [
        "getting-started/install",
        "getting-started/quickstart",
        "getting-started/hardware-requirements",
        "getting-started/project-template",
      ],
      collapsed: false,
    },
    {
      type: "category",
      label: "Writing Programs",
      items: [
        "writing-programs/basics",
        "writing-programs/compiling",
        "writing-programs/cycle-tracking",
        "writing-programs/inputs-and-outputs",
        "writing-programs/patched-crates",
        "writing-programs/precompiles",
        "writing-programs/proof-aggregation",
        "writing-programs/setup",
      ],
      collapsed: true,
    },
    {
      type: "category",
      label: "Generating Proofs",
      items: [
        "generating-proofs/basics",
        "generating-proofs/setup",
        "generating-proofs/proof-types",
        "generating-proofs/recommended-workflow",
        "generating-proofs/sp1-sdk-faq",
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
      collapsed: true,
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
    },
    {
      type: "category",
      label: "Developers",
      items: [
        "developers/common-issues",
        "developers/usage-in-ci",
        "developers/building-circuit-artifacts",
        "developers/rv32im-deviations",
      ],
    },
    "what-is-a-zkvm",
    "why-use-sp1",
  ],
};

export default sidebars;
