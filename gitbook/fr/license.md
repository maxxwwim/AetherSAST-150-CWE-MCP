# Licence

Conditions de licence, usages non commerciaux autorisés, restrictions commerciales et métadonnées des composants de `aether-engine`.

## Licence PolyForm Noncommercial 1.0.0

`aether-engine` (`AetherScope / AetherSAST`) est publié sous la licence **PolyForm Noncommercial License 1.0.0** (`PolyForm-Noncommercial-1.0.0`), définie dans le fichier `LICENSE` à la racine du dépôt.

* **Texte officiel de la licence :** [https://polyformproject.org/licenses/noncommercial/1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0)
* **Mention obligatoire (`Required Notice`) :**

```text
Required Notice: Copyright (c) 2026 maxxwwim (https://github.com/maxxwwim)
```

{% hint style="warning" %}
**L'usage commercial est interdit** par la licence `PolyForm-Noncommercial-1.0.0`. Toute utilisation de `aether-engine` dans un cadre commercial nécessite l'obtention d'une licence commerciale distincte auprès du concédant.
{% endhint %}

## Usages autorisés

Selon le fichier `LICENSE`, les licences de droit d'auteur et de brevet vous autorisent à utiliser, copier, modifier et distribuer le logiciel ou créer des œuvres dérivées **uniquement à des fins non commerciales autorisées** :

| Catégorie | Périmètre autorisé (`LICENSE`) |
|---|---|
| **Fins non commerciales** | Toute finalité dépourvue de caractère commercial. |
| **Usages personnels** | Recherche, expérimentation, tests visant le savoir public, étude personnelle, divertissement privé, projets de loisir, activités amateurs ou observance religieuse sans application commerciale prévue. |
| **Organisations non commerciales** | Organisations caritatives, établissements d'enseignement, organismes de recherche publique, organismes de sécurité ou de santé publique, organisations de protection de l'environnement et **institutions gouvernementales quelle que soit leur source de financement**. |
| **Usage loyal (*Fair Use*)** | Les droits légaux de citation, d'exception ou d'usage loyal restent pleinement préservés. |

## Conditions, restrictions et recours

* **Préservation des mentions** : Pour toute distribution d'une copie ou d'une œuvre dérivée, vous devez fournir une copie des termes de la licence (ou son URL) et conserver intacte chaque ligne `Required Notice:`.
* **Aucune sous-licence ni cession** : Vous ne pouvez ni sous-licencier ni transférer les droits accordés par `PolyForm-Noncommercial-1.0.0`.
* **Défense en matière de brevets** : Si vous formulez par écrit une réclamation alléguant que le logiciel enfreint un brevet, votre licence de brevet prend fin immédiatement (y compris pour les travaux effectués au nom de votre entreprise si celle-ci est à l'origine de la réclamation).
* **Manquements et délai de régularisation de 32 jours** : Après réception d'une première notification écrite de violation, vous disposez de **32 jours** pour vous mettre en conformité ; à défaut, toutes les licences prennent fin immédiatement. Toute récidive entraîne une résiliation immédiate sans délai de grâce.
* **Absence de garantie et de responsabilité** : Le logiciel est fourni **« en l'état »** (*as is*), sans aucune garantie expresse ou implicite, et sans responsabilité du concédant.

## Métadonnées de licence par composant

| Composant | Fichier manifeste | Version | Licence déclarée |
|---|---|---|---|
| **Racine du workspace (`aether-engine`)** | `Cargo.toml` | `2.6.0` | `PolyForm-Noncommercial-1.0.0` (`license-file = "LICENSE"`) |
| **Les 7 crates du workspace** | `crates/*/Cargo.toml` | `2.6.0` (workspace) | `PolyForm-Noncommercial-1.0.0` (héritée via `license.workspace = true`) |
| **Interface Frontend (`aetherscope-ui`)** | `crates/desktop-shell/ui/package.json` | `2.6.0` | `"private": true` (couverte par le fichier `LICENSE` racine) |
| **Runner AetherCraft (`aether-mc-runner`)** | `apps/aethercraft/runner/Cargo.toml` | `1.0.0` | `PolyForm-Noncommercial-1.0.0` |
