import pkgutil
pkgutil.resolve_name('os').environ_copy = 1
pkgutil.resolve_name('sys').path[0] = 'constructed'
