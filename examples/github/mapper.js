module.exports.handler = async function(input) {
    const claims = input.claims;

    if (claims.repository_owner !== "octo-org") {
        return { allow: false };
    }

    const interestingClaims = [
        "actor",
        "event_name",
        "ref",
        "repository",
        "run_attempt",
        "run_id",
        "run_number",
        "sha",
        "workflow"
    ];

    const tags = Object.fromEntries(interestingClaims.map(name => [
        name,
        [claims[name]]
    ]));

    claims["https://aws.amazon.com/tags"] = {
        principal_tags: tags,
        transitive_tag_keys: [],
    };

    return { allow: true, claims };
}
