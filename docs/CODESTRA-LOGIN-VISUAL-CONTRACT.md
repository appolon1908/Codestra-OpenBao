# Codestra OpenBao login visual contract

## Purpose

Human OpenBao access uses the existing Codestra Keycloak OIDC boundary. The shared credential and MFA experience must therefore use the same black-and-white Codestra identity language as the social application rather than maintaining a separate OpenBao-branded password page.

This repository does **not** fork or patch the upstream OpenBao UI for cosmetic purposes. OpenBao remains responsible for its auth-method selection, token session and policy enforcement; Keycloak remains responsible for user credentials, MFA and the shared Codestra identity appearance.

## Visual contract

The identity surface is owned by `ingtrader21-spec/Keycloak` and inherits the visual tokens established by `ingtrader21-spec/social.codestra.co`:

- page background: `#0b0b0b`;
- auth panel: `#171717`;
- primary text and CTA: white;
- secondary text: `#a1a1aa`;
- subtle white borders;
- 16 px panel radius and 10 px controls;
- visible keyboard focus and reduced-motion support;
- no Starlink branding, images or copied assets.

The OpenBao OIDC client is `openbao-secrets` with application URL `https://bao.codestra.media`. Browser redirects remain restricted to the reviewed OpenBao callback paths and localhost CLI callback. Access continues to require dedicated secrets roles and MFA defined by the Codestra identity contract.

## Security boundary

The visual change must never:

- add a local Codestra password form to OpenBao;
- expose OpenBao's native port publicly;
- weaken the source-network allowlist around `bao.codestra.media`;
- bypass OpenBao policy after Keycloak authentication;
- put client secrets, tokens, unseal/recovery material or credentials in Git, HTML, CSS, logs or screenshots;
- grant observability roles access to secrets roles.

OpenBao's own login selector may still appear before the OIDC redirect. That is intentional upstream application behavior. The shared Codestra visual contract applies to the credential/MFA identity surface, not to a maintained fork of OpenBao's application UI.

## Acceptance

Source-level acceptance requires the Keycloak `codestra-identity` theme to inherit the shared `codestra` visual base and the `openbao-secrets` browser client to remain bound to the reviewed Codestra OIDC issuer and callback allowlist.

Production visual acceptance additionally requires a rendered browser capture of the OpenBao OIDC flow and the Keycloak credential/MFA pages at desktop and narrow widths. Source configuration alone does not certify a live production login.
