const { PrismaClient } = require('../backend/node_modules/@prisma/client');
const prisma = new PrismaClient();

async function run() {
  try {
    const all = await prisma.analysis.findMany({
      include: {
        behaviorEvents: true,
        siemEvents: true,
        mitreTechniques: true,
      }
    });

    console.log(`Total analyses in DB: ${all.length}`);
    const with4Behaviors = all.filter(a => a.behaviorEvents.length === 4);
    console.log(`Analyses with exactly 4 behavior events: ${with4Behaviors.length}`);
    for (const a of with4Behaviors) {
      console.log('--- Analysis with 4 behavior events ---');
      console.log({
        analysisId: a.analysisId,
        fileName: a.fileName,
        originalFileName: a.originalFileName,
        uploadedAt: a.uploadedAt,
        riskScore: a.riskScore,
        threatLevel: a.threatLevel,
        siemCount: a.siemEvents.length,
        behaviorEvents: a.behaviorEvents
      });
    }

    const anyBehaviors = all.filter(a => a.behaviorEvents.length > 0);
    console.log(`Analyses with > 0 behavior events: ${anyBehaviors.length}`);
    for (const a of anyBehaviors) {
      console.log(`Analysis ${a.analysisId} (${a.originalFileName}): ${a.behaviorEvents.length} behaviors, ${a.siemEvents.length} siemEvents`);
    }

  } catch (err) {
    console.error('Error:', err);
  } finally {
    await prisma.$disconnect();
  }
}

run();
