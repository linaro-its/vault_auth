from setuptools import setup

setup(name='vault_auth',
      version='0.4',
      description='Handles AWS IAM Auth with Hashicorp Vault',
      url='http://github.com/linaro-its/vault_auth',
      author='Linaro IT Services',
      author_email='it-services@linaro.org',
      install_requires=[
          "requests",
          "boto3"
      ],
      packages=['vault_auth'],
      zip_safe=False)
