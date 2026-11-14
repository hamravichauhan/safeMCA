class Safemca < Formula
  desc "Sub-millisecond security proxy and airbag for AI agents using MCP"
  homepage "https://github.com/hamravichauhan/safeMCA"
  version "0.1.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/hamravichauhan/safeMCA/releases/download/v0.1.1/safemca-macos-arm64.tar.gz"
    else
      url "https://github.com/hamravichauhan/safeMCA/releases/download/v0.1.1/safemca-macos-x86_64.tar.gz"
    end
  end

  on_linux do
    url "https://github.com/hamravichauhan/safeMCA/releases/download/v0.1.1/safemca-linux-x86_64.tar.gz"
  end

  def install
    bin.install "safemca"
    bin.install "mcp-guard"
  end

  test do
    assert_match "safemca", shell_output("#{bin}/safemca --version")
    system "#{bin}/safemca", "test"
  end
end
