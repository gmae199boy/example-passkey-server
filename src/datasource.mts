import { DataSource } from "typeorm";
import * as Entity from "./Entities/index.mjs";

export let AppDataSource: DataSource;

type DataSourceParameters = {
  logging: boolean;
  poolSize?: number;
};

const getDataSource = (logging: boolean, poolSize?: number): DataSource => {
  const mysqlDataSource = new DataSource({
    type: "mysql",
    port: parseInt(process.env.DB_PORT as string),
    database: process.env.DB_NAME as string,
    host: process.env.DB_HOST as string,
    username: process.env.DB_USER as string,
    password: process.env.DB_PASSWORD as string,
    entities: Object.values(Entity),
    timezone: "Z",
    logging,
    poolSize,
  });

  return mysqlDataSource;
};

export const dataSourceInit = async ({
  logging = false,
  poolSize,
}: DataSourceParameters) => {
  AppDataSource = getDataSource(logging, poolSize);

  await AppDataSource.initialize()
    .then(() => {
      console.log("Data Source has been initialized!");
    })
    .catch((err) => {
      console.error("Error during Data Source initialization", err);
      process.exit(1);
    });
};

export const syncDb = async (dropBeforeSync = false) => {
  AppDataSource = getDataSource(true);

  await AppDataSource.initialize();

  await AppDataSource.synchronize(dropBeforeSync);

  await AppDataSource.destroy();
};

export const disconnectDb = async () => {
  await AppDataSource.destroy();
};
