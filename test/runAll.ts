async function runAll() {
  await (await import('./validator.test')).run();
  await (await import('./sender.test')).run();
  await (await import('./receiver.test')).run();
  await (await import('./timestampCiphertext.test')).run();
}

runAll().catch((err) => {
  console.error(err);
  process.exit(1);
});
