# Dynamic Performance Badges Setup

To display real-time performance metrics on your `README.md`, we use GitHub Actions to run the tests, extract the latency metrics, and push them to a GitHub Gist. Shields.io then reads that Gist to render the badges.

## 1. Create a GitHub Gist
1. Go to https://gist.github.com/ and create a new public gist (the contents don't matter, just name it `metrics.json`).
2. Copy the **Gist ID** from the URL (e.g., `https://gist.github.com/your-username/GIST_ID`).
3. Create a GitHub Personal Access Token (PAT) with the `gist` scope.
4. Go to your repository settings -> Secrets and variables -> Actions, and add the token as `GIST_SECRET`.

## 2. Update your GitHub Actions Workflow
Add this step to your `.github/workflows/python-app.yml` (or wherever your tests run) *after* your tests complete:

```yaml
      - name: Generate Iron Dome Badge
        uses: Schneegans/dynamic-badges-action@v1.7.0
        with:
          auth: ${{ secrets.GIST_SECRET }}
          gistID: YOUR_GIST_ID_HERE
          filename: iron_dome_latency.json
          label: Iron Dome Latency
          message: ${{ fromJson(env.METRICS).iron_dome_ms }}ms
          color: green
          valColorRange: ${{ fromJson(env.METRICS).iron_dome_ms }}
          maxColorRange: 5.0
          minColorRange: 0.1
        env:
          METRICS: ${{ steps.read_json.outputs.content }}
          
      # Add similar steps for vault_ms and cache_ms changing the filename and label.
```

*(Note: You will need a step to read the JSON into the `METRICS` env var before calling the badge action, e.g., using `jq` or a python script to set the step output).*

## 3. Add to README.md
Finally, add the Shields.io endpoints to the top of your `README.md`:

```markdown
![Iron Dome Latency](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/YOUR_USERNAME/YOUR_GIST_ID/raw/iron_dome_latency.json)
![Vault Latency](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/YOUR_USERNAME/YOUR_GIST_ID/raw/vault_latency.json)
![Cache Latency](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/YOUR_USERNAME/YOUR_GIST_ID/raw/cache_latency.json)
```
