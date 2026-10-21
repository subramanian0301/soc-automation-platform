-- CreateTable
CREATE TABLE `Analysis` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `fileName` VARCHAR(191) NOT NULL,
    `originalFileName` VARCHAR(191) NOT NULL,
    `fileSize` INTEGER NOT NULL,
    `fileType` VARCHAR(191) NOT NULL,
    `mimeType` VARCHAR(191) NOT NULL,
    `uploadedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `analysisTime` DATETIME(3) NULL,
    `hostname` VARCHAR(191) NULL,
    `username` VARCHAR(191) NULL,
    `operatingSystem` VARCHAR(191) NULL,
    `riskScore` INTEGER NULL,
    `threatLevel` ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NULL,
    `recommendation` TEXT NULL,
    `status` ENUM('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED') NOT NULL DEFAULT 'PENDING',
    `source` TEXT NULL,
    `isArchived` BOOLEAN NOT NULL DEFAULT false,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `Analysis_analysisId_key`(`analysisId`),
    INDEX `Analysis_analysisId_idx`(`analysisId`),
    INDEX `Analysis_createdAt_idx`(`createdAt`),
    INDEX `Analysis_threatLevel_idx`(`threatLevel`),
    INDEX `Analysis_isArchived_idx`(`isArchived`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `FileMetadata` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `filePath` VARCHAR(191) NOT NULL,
    `storageKey` VARCHAR(191) NOT NULL,
    `extension` VARCHAR(191) NOT NULL,
    `headerMagic` VARCHAR(191) NULL,
    `encoding` VARCHAR(191) NULL,

    UNIQUE INDEX `FileMetadata_analysisId_key`(`analysisId`),
    INDEX `FileMetadata_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Hash` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `md5` VARCHAR(191) NULL,
    `sha1` VARCHAR(191) NULL,
    `sha256` VARCHAR(191) NULL,
    `ssdeep` VARCHAR(191) NULL,

    UNIQUE INDEX `Hash_analysisId_key`(`analysisId`),
    INDEX `Hash_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `FileProperty` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `entropy` DOUBLE NULL,
    `digitalSignature` VARCHAR(191) NULL,
    `isPacked` BOOLEAN NULL,
    `packer` VARCHAR(191) NULL,
    `imports` JSON NULL,
    `suspiciousApis` JSON NULL,

    UNIQUE INDEX `FileProperty_analysisId_key`(`analysisId`),
    INDEX `FileProperty_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `YaraResult` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `ruleName` VARCHAR(191) NOT NULL,
    `namespace` VARCHAR(191) NULL,
    `tags` JSON NULL,
    `meta` JSON NULL,
    `description` VARCHAR(191) NULL,

    INDEX `YaraResult_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `VirusTotalResult` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `positives` INTEGER NOT NULL,
    `total` INTEGER NOT NULL,
    `permalink` VARCHAR(191) NULL,
    `scanDate` VARCHAR(191) NULL,
    `detections` JSON NULL,

    UNIQUE INDEX `VirusTotalResult_analysisId_key`(`analysisId`),
    INDEX `VirusTotalResult_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Ioc` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `type` VARCHAR(191) NOT NULL,
    `value` VARCHAR(191) NOT NULL,
    `category` VARCHAR(191) NULL,
    `confidence` INTEGER NULL,
    `description` VARCHAR(191) NULL,

    INDEX `Ioc_analysisId_idx`(`analysisId`),
    INDEX `Ioc_type_value_idx`(`type`, `value`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `MitreTechnique` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `tactic` VARCHAR(191) NOT NULL,
    `techniqueId` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `description` TEXT NULL,

    INDEX `MitreTechnique_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `BehaviorEvent` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `eventType` VARCHAR(191) NOT NULL,
    `action` VARCHAR(191) NOT NULL,
    `target` VARCHAR(191) NOT NULL,
    `details` TEXT NULL,
    `timestamp` DATETIME(3) NULL,

    INDEX `BehaviorEvent_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `SandboxResult` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `sandboxName` VARCHAR(191) NOT NULL,
    `verdict` VARCHAR(191) NOT NULL,
    `score` INTEGER NULL,
    `details` JSON NULL,

    INDEX `SandboxResult_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `SiemEvent` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `eventId` VARCHAR(191) NULL,
    `sourceIp` VARCHAR(191) NULL,
    `destIp` VARCHAR(191) NULL,
    `sourcePort` INTEGER NULL,
    `destPort` INTEGER NULL,
    `protocol` VARCHAR(191) NULL,
    `action` VARCHAR(191) NULL,
    `severity` VARCHAR(191) NULL,
    `rawEvent` TEXT NOT NULL,
    `timestamp` DATETIME(3) NOT NULL,

    INDEX `SiemEvent_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Incident` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `title` VARCHAR(191) NOT NULL,
    `severity` ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NULL,
    `status` VARCHAR(191) NOT NULL,
    `reason` VARCHAR(191) NOT NULL,
    `assignedTo` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `Incident_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Case` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `caseNumber` VARCHAR(191) NOT NULL,
    `title` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `priority` VARCHAR(191) NOT NULL,
    `summary` TEXT NULL,

    UNIQUE INDEX `Case_caseNumber_key`(`caseNumber`),
    INDEX `Case_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `SoarExecution` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `actionName` VARCHAR(191) NOT NULL,
    `target` VARCHAR(191) NULL,
    `status` ENUM('COMPLETED', 'PENDING_APPROVAL', 'RECOMMENDED', 'FAILED') NOT NULL,
    `executionLog` TEXT NULL,
    `timestamp` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `SoarExecution_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Asset` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `assetName` VARCHAR(191) NOT NULL,
    `ipAddress` VARCHAR(191) NULL,
    `macAddress` VARCHAR(191) NULL,
    `assetType` VARCHAR(191) NULL,
    `criticality` VARCHAR(191) NULL,

    INDEX `Asset_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Endpoint` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `hostname` VARCHAR(191) NOT NULL,
    `osVersion` VARCHAR(191) NULL,
    `agentStatus` VARCHAR(191) NULL,
    `lastSeen` DATETIME(3) NULL,

    INDEX `Endpoint_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Vulnerability` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NOT NULL,
    `cveId` VARCHAR(191) NOT NULL,
    `title` VARCHAR(191) NOT NULL,
    `cvssScore` DOUBLE NULL,
    `severity` VARCHAR(191) NULL,
    `description` TEXT NULL,

    INDEX `Vulnerability_analysisId_idx`(`analysisId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `AuditLog` (
    `id` VARCHAR(191) NOT NULL,
    `analysisId` VARCHAR(191) NULL,
    `action` VARCHAR(191) NOT NULL,
    `performedBy` VARCHAR(191) NOT NULL,
    `timestamp` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `details` TEXT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `FileMetadata` ADD CONSTRAINT `FileMetadata_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Hash` ADD CONSTRAINT `Hash_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `FileProperty` ADD CONSTRAINT `FileProperty_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `YaraResult` ADD CONSTRAINT `YaraResult_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `VirusTotalResult` ADD CONSTRAINT `VirusTotalResult_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Ioc` ADD CONSTRAINT `Ioc_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `MitreTechnique` ADD CONSTRAINT `MitreTechnique_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `BehaviorEvent` ADD CONSTRAINT `BehaviorEvent_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `SandboxResult` ADD CONSTRAINT `SandboxResult_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `SiemEvent` ADD CONSTRAINT `SiemEvent_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Incident` ADD CONSTRAINT `Incident_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Case` ADD CONSTRAINT `Case_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `SoarExecution` ADD CONSTRAINT `SoarExecution_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Asset` ADD CONSTRAINT `Asset_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Endpoint` ADD CONSTRAINT `Endpoint_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Vulnerability` ADD CONSTRAINT `Vulnerability_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `AuditLog` ADD CONSTRAINT `AuditLog_analysisId_fkey` FOREIGN KEY (`analysisId`) REFERENCES `Analysis`(`analysisId`) ON DELETE SET NULL ON UPDATE CASCADE;
