# About

This is a `flask` app t explain how to login with `3bot`



### Run 

- `pip3 install flask pynacl`
- `export FLASK_APP=example.py&&flask run`

### Generate a private signing key and use in your configuration

This is already generated inside the `example` app
so no need for this step here.
But it requires if you're doing some implementation and
you want to save the private key used in configuration

```
python3 -c "import nacl.signing;print(nacl.signing.SigningKey.generate().encode(nacl.encoding.Base64Encoder))"
```