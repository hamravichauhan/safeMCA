#!/usr/bin/env node

const os = require("os");
const path = require("path");
const fs = require("fs");
const { spawnSync } = require("child_process");
const https = require("https");

const VERSION = "v0.1.0";
const REPO = "hamravichauhan/safeMCA";

function getBinaryName() {
  return os.platform() === "win32" ? "safemca.exe" : "safemca";
}

function getAssetFilename() {
  const platform = os.platform();
  const arch = os.arch();

  if (platform === "darwin") {
    return arch === "arm64" ? "safemca-macos-arm64.tar.gz" : "safemca-macos-x86_64.tar.gz";
  } else if (platform === "linux") {
    if (arch === "x64") return "safemca-linux-x86_64.tar.gz";
  } else if (platform === "win32") {
    if (arch === "x64") return "safemca-windows-x86_64.tar.gz";
  }

  throw new Error(`Unsupported platform/architecture: ${platform}-${arch}`);
}

function getCacheDir() {
  const home = os.homedir();
  const cacheDir = path.join(home, ".safemca", "bin");
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, { recursive: true });
  }
  return cacheDir;
}

function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);
    https.get(url, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        // Follow redirect (GitHub release assets redirect to AWS S3)
        return downloadFile(response.headers.location, destPath).then(resolve).catch(reject);
      }

      if (response.statusCode !== 200) {
        return reject(new Error(`Download failed with HTTP ${response.statusCode}`));
      }

      response.pipe(file);
      file.on("finish", () => {
        file.close(() => resolve(destPath));
      });
    }).on("error", (err) => {
      fs.unlink(destPath, () => {});
      reject(err);
    });
  });
}

async function ensureBinary() {
  const binaryName = getBinaryName();
  const cacheDir = getCacheDir();
  const binaryPath = path.join(cacheDir, `${VERSION}-${binaryName}`);

  // Check if already downloaded
  if (fs.existsSync(binaryPath)) {
    return binaryPath;
  }

  // Also check if running from safeMCA local repo build
  const localRepoBinary = path.join(__dirname, "..", "..", "target", "release", binaryName);
  if (fs.existsSync(localRepoBinary)) {
    return localRepoBinary;
  }

  const assetName = getAssetFilename();
  const downloadUrl = `https://github.com/${REPO}/releases/download/${VERSION}/${assetName}`;
  const archivePath = path.join(cacheDir, `${VERSION}-${assetName}`);

  process.stderr.write(`[safeMCA] Downloading standalone binary for ${os.platform()}-${os.arch()}...\n`);

  try {
    await downloadFile(downloadUrl, archivePath);

    // Extract archive using system tar
    spawnSync("tar", ["-xzf", archivePath, "-C", cacheDir], { stdio: "inherit" });

    // Move extracted binary to versioned path
    const extractedBinary = path.join(cacheDir, binaryName);
    if (fs.existsSync(extractedBinary)) {
      if (extractedBinary !== binaryPath) {
        fs.renameSync(extractedBinary, binaryPath);
      }
      fs.chmodSync(binaryPath, 0o755);
    }

    // Cleanup archive
    if (fs.existsSync(archivePath)) {
      fs.unlinkSync(archivePath);
    }

    return binaryPath;
  } catch (err) {
    process.stderr.write(`[safeMCA Error] Failed to download prebuilt binary: ${err.message}\n`);
    process.stderr.write(`You can also build from source with: cargo install safemca\n`);
    process.exit(1);
  }
}

async function main() {
  const binaryPath = await ensureBinary();
  const result = spawnSync(binaryPath, process.argv.slice(2), {
    stdio: "inherit",
    env: process.env,
  });

  process.exit(result.status ?? 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
