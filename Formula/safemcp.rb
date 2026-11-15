class Safemcp < Formula
  desc "Sub-millisecond security proxy and airbag for AI agents using MCP"
  homepage "https://github.com/hamravichauhan/safeMCP"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/hamravichauhan/safeMCP/releases/download/v0.1.0/safemcp-macos-arm64.tar.gz"
    else
      url "https://github.com/hamravichauhan/safeMCP/releases/download/v0.1.0/safemcp-macos-x86_64.tar.gz"
    end
  end

  on_linux do
    url "https://github.com/hamravichauhan/safeMCP/releases/download/v0.1.0/safemcp-linux-x86_64.tar.gz"
  end

  def install
    bin.install "safemcp"
    bin.install "mcp-guard"
    bin.install "safemca" if File.exist?("safemca")
  end

  test do
    assert_match "safemcp", shell_output("#{bin}/safemcp --version")
    system "#{bin}/safemcp", "test"
  end
end
