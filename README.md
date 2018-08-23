# iron
Serialize and encrypt any Elixir `term()` and send it around.

"iron is a cryptographic utility for sealing a JSON object using symmetric key encryption with message integrity verification. Or in other words, it lets you encrypt an object, send it around (in cookies, authentication credentials, etc.), then receive it back and decrypt it. The algorithm ensures that the message was not tampered with, and also provides a simple mechanism for password rotation." - [iron](https://github.com/hueniverse/iron)


## Examples

```elixir
    iex> sealed = Iron.seal(%{"a" => 1, "b" => 2, "c" => [3, 4, 5], "d" => %{ "e" => "f" }}, "some_not_random_password_that_is_also_long_enough")
    "Fe26.2**CECQFMECC7VPJBP4IJFKTSG1VTNM41Q3G3I7H195218HV0AHP5A0====*RhZkdeZnjMi2AL0oB7L_Ww*v2BY2UeJknYojSbR5wmHQf-nF9UKcTCWtvL28-N2-9WePDiHgN2MUopWq1vazxv4*1531861757834*OL8TRM1NUPM3COATCES9GHG7UBV4FDONL8P6OKH5FHK0E7P7LS80====*k3TdLkCXsDLHMm6ThVBtmbLZJZUNAhzJEsNxg5D6cIk"

    iex> Iron.unseal(sealed, "some_not_random_password_that_is_also_long_enough")
    %{"a" => 1, "b" => 2, "c" => [3, 4, 5], "d" => %{ "e" => "f" }}
```

## Documentation

[hex documentation for iron](https://hexdocs.pm/iron)


## Installation

```elixir
def deps do
  [{:iron, "~> 0.1.0"}]
end
```

## Acknowledgement

This is an Elixr implementation of the excellent [iron](https://github.com/hueniverse/iron).

## LICENSE

(The MIT License)

Copyright (c) 2018 Benjamin Schultzer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS,' WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
