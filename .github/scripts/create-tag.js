module.exports = async ({ github, context }, tagName) => {
    try {
        await github.rest.git.createRef({
            owner: context.repo.owner,
            repo: context.repo.repo,
            ref: `refs/tags/${tagName}`,
            sha: context.sha,
            force: true,
        });

        await github.rest.git.createWorkflowDispatch({
            owner: context.repo.owner,
            repo: context.repo.repo,
            workflow_id: 'docker-publish-gnark.yml',
            ref: tagName,
        });

        await github.rest.git.createWorkflowDispatch({
            owner: context.repo.owner,
            repo: context.repo.repo,
            workflow_id: 'docker-publish.yml',
            ref: tagName,
        });
    } catch (err) {
        console.error(`Failed to create tag: ${tagName}`);
        console.error(err);
    }
};