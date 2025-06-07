const bcrypt = require('bcryptjs');

async function genereljBcryptHash(jelszo) {
  try {
    // A saltRounds értéke határozza meg a hashelés erősségét (és idejét).
    // Általában 10-12 közötti érték jó kompromisszum.
    const saltRounds = 10;
    const hash = await bcrypt.hash(jelszo, saltRounds);
    return hash;
  } catch (error) {
    console.error("Hiba a bcrypt hashelés során:", error);
    return null;
  }
}

async function main() {
  const szo = "alma";
  const bcryptHash = await genereljBcryptHash(szo);

  if (bcryptHash) {
    console.log(`Az "${szo}" szó bcrypt hash-e (egy lehetséges változat):`);
    console.log(bcryptHash);

    // Példa az ellenőrzésre (opcionális, csak demonstráció)
    // const helyesJelszo = await bcrypt.compare("alma", bcryptHash);
    // console.log("\nEllenőrzés 'alma' szóval:", helyesJelszo); // Ennek true-nak kell lennie

    // const helytelenJelszo = await bcrypt.compare("körte", bcryptHash);
    // console.log("Ellenőrzés 'körte' szóval:", helytelenJelszo); // Ennek false-nak kell lennie
  }
}

main();
