defmodule Iron.Mixfile do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :iron,
      version: @version,
      elixir: "~> 1.5",
      name: "iron",
      source_url: "https://github.com/schultzer/iron",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.2"},
      {:kryptiles, "~> 0.1.0"},
      {:ex_doc, "~> 0.21", only: :dev, runtime: false},
    ]
  end
  defp description do
    """
    Serialize and encrypt any Elixir `term()` and send it around.
    """
  end

  defp package do
    [
      name: :iron,
      maintainers: ["Benjamin Schultzer"],
      licenses: ~w(MIT),
      links: links(),
      files: ~w(CHANGELOG* README* lib mix.exs)
    ]
  end

  def docs do
    [
      source_ref: "v#{@version}",
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end

  def links do
    %{
      "GitHub"    => "https://github.com/schultzer/iron",
      "Readme"    => "https://github.com/schultzer/iron/blob/v#{@version}/README.md",
      "Changelog" => "https://github.com/schultzer/iron/blob/v#{@version}/CHANGELOG.md"
    }
  end
end
