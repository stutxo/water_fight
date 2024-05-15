# Leptos Start Template

Use this template to start a Leptos project for GitHub Pages.

## Setup

When you run the build script, the `wasm/html` file will be moved to the `docs` folder which is where github pages will deploy from.

### Testing Locally

To test your project locally, use the following command:

```bash
build.sh dev
```

### Configuration for GitHub Pages

To set up GitHub Pages:

1. In your GitHub repository, go to **Settings** > **Pages**.
2. Choose **Deploy from a branch**.
3. Select the `main` branch and set the folder to `/docs`.
4. Click **Save**.

## Deployment

When you are ready to publish changes to your website, use the release build command:

```bash
build.sh release
```

then commit your changes to GitHub, and your website will be redeployed.
