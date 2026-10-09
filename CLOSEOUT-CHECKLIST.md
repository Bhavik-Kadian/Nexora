# Close-out checklist

The steps only the repository's owner can take, left over from the close-out on 2026-10-10. The close-out itself did none of them: it never revokes a token, deletes a cloud resource, removes someone's access or archives a repository. Tick them off as you go.

## 1. Revoke or rotate the tokens that were used

- [ ] **The GitHub CLI login** (`gh`), used for the demo pull requests and the close-out. When this laptop no longer needs it: `gh auth logout -h github.com`, then revoke **GitHub CLI** under Authorized OAuth Apps at <https://github.com/settings/applications>.
- [ ] **Personal access tokens.** The project used none that the close-out knows of. Check <https://github.com/settings/tokens> (classic and fine-grained) and delete any you made for it.
- [ ] **Git's saved GitHub login.** Git Credential Manager keeps one for `git push`. Remove it in Windows' Credential Manager (Windows Credentials, `git:https://github.com`) if this laptop should no longer push.
- [ ] **The Azure AI key.** It was never committed and is not stored on GitHub, only in `.securegate\ai.json` on this laptop, but it works for as long as it is not rotated. Rotate it: in the Azure portal, open the Azure AI Foundry resource, then **Keys and Endpoint**, and regenerate both keys (or the commands below). If you still use the agents, run `securegate ai-setup` with the new key.
- [ ] **The ACME Pay admin token and dashboard password:** nothing to do. They were never created, because the ACME Pay provider was never built.
- [ ] **Other model API keys:** nothing to do. The agents use only the Azure AI Foundry key.

## 2. Azure: kept up for now

The only Azure resource is the Azure AI Foundry resource, with the model deployment that the AI agents use. It was kept up at the close-out. Azure bills each model call, not the idle resource, but its keys work until they are rotated.

Rotate its keys, with the Azure CLI:

```powershell
winget install --id Microsoft.AzureCLI -e
az login
az cognitiveservices account list --query "[].{name:name, group:resourceGroup, location:location}" -o table
az cognitiveservices account keys regenerate --name <name> --resource-group <group> --key-name Key1
az cognitiveservices account keys regenerate --name <name> --resource-group <group> --key-name Key2
```

When you no longer need it, delete it. Azure keeps a deleted AI resource for a while; `purge` removes it for good:

```powershell
az cognitiveservices account delete --name <name> --resource-group <group>
az cognitiveservices account list-deleted
az cognitiveservices account purge --name <name> --resource-group <group> --location <location>
```

If its resource group holds nothing else, `az group delete --name <group>` removes the group too. Then delete `.securegate\ai.json` on this laptop.

## 3. Secrets and variables on GitHub

At the close-out, the repository had **no** Actions secrets and **no** Actions variables (`gh secret list` and `gh variable list` were empty), so nothing points at a service that is gone. The merge gate's AI step says the agents were not asked.

- [ ] Optional, while Azure is up: to get AI advice in pull request comments, set the secret `SECUREGATE_AI_KEY` and the variables `SECUREGATE_AI_ENDPOINT` and `SECUREGATE_AI_DEPLOYMENT` ("The AI agents" in [The two gates](docs/merge-gate.md)).
- [ ] If you set them: when you delete the Azure resource, remove them with `gh secret delete SECUREGATE_AI_KEY`, `gh variable delete SECUREGATE_AI_ENDPOINT` and `gh variable delete SECUREGATE_AI_DEPLOYMENT`, run in the SecureGate folder.

## 4. Who can change the repositories

- **Nexora** (this repository) has one collaborator: you, as admin. Add teammates under Settings, then Collaborators, if they should be able to push.
- **Nexora-backup** (the old Nexora repository) has four collaborators with write access. Remove them under Settings, then Collaborators, when they no longer need it, or archive the repository (step 6).

## 5. Archiving the repository (decided: no)

The repository stays open; its README says the project is completed and not actively maintained. If you change your mind:

```powershell
gh repo archive Bhavik-Kadian/Nexora --yes
```

An archived repository is read-only for everyone. `gh repo unarchive Bhavik-Kadian/Nexora --yes` undoes it.

## 6. The other repositories

- [ ] **Nexora-backup**, the old Nexora: its first README and copies of early branches, all of them also in Nexora. Archive it with `gh repo archive Bhavik-Kadian/Nexora-backup --yes`, or delete it: `gh auth refresh -h github.com -s delete_repo`, then `gh repo delete Bhavik-Kadian/Nexora-backup --yes`.
- [ ] **securegate-action-demo**, the scratch repository where the GitHub Action was tried on real pull requests. Its `main` has the workflow from [Protect any repository](docs/install.md), at `@v1.0.0`. Pull request #1, a harmless change, is green and still open; #2, a fake ACME Pay token, went red under rule 8 and was closed, and its branch `try/fake-token` still holds that fake token, which unlocks nothing. Keep it as a working example, or delete it the same way.

## 7. Team credits

- [ ] The README credits only the lead developer by name. Add the other names and roles when you have them.
