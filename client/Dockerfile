# client/Dockerfile et server/Dockerfile
FROM alpine:3.18

# Installation des outils de base pour le C
RUN apk add --no-cache gcc musl-dev make

WORKDIR /app

# On ne copie pas le code ici, on utilisera un volume 
# pour que les modifications soient instantanées.
CMD ["sh"]
