<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Project architecture

- Keep all future Python service communication behind `src/lib/scamlens-api.ts`; the frontend must never synthesize ML predictions.
- Keep shared cybersecurity interface patterns in `src/components/scamlens`; routes compose these patterns instead of duplicating them.
- Validate every FastAPI response with Zod and derive dashboard/analytics only from returned history; this prevents fabricated or malformed ML data from entering the UI.
