const { PrismaClient } = require('../backend/node_modules/@prisma/client');
const prisma = new PrismaClient();

async function run() {
  try {
    const a = await prisma.analysis.findUnique({
      where: { analysisId: 'analysis_00144a95b392488d' },
      include: {
        fileMetadata: true,
        hashes: true,
        fileProperties: true,
        yaraResults: true,
        virusTotalResult: true,
        iocs: true,
        mitreTechniques: true,
        behaviorEvents: true,
        sandboxResults: true,
        siemEvents: true,
        incidents: true,
        cases: true,
        soarExecutions: true,
        assets: true,
        endpoints: true,
        vulnerabilities: true,
      }
    });
    console.log(JSON.stringify(a, null, 2));
  } catch (err) {
    console.error('Error:', err);
  } finally {
    await prisma.$disconnect();
  }
}

run();
