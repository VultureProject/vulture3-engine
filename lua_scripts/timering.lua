-- redis-cli --eval timering.lua ip time , 127.0.0.1 $(date +%s)
-- redis-cli SCRIPT LOAD "$(cat timering.lua)"
-- EVALSHA 371fcccd5e47fa6a7b68149d1903225e9a482e68 2 ip time 127.0.0.1 TIMESTAMP

local ipkey = ARGV[1] .. "_rqs"
local time = ARGV[2]
local last_insertion_time = redis.call("HGET", ipkey, "ts")
if (last_insertion_time == false) then last_insertion_time = 0 end
local elapsed_time = time - last_insertion_time
if (elapsed_time >= 60) then -- Init / Time's over
	redis.call("HMSET", ipkey, "idx", 0, "sum", 1, "ts", 0,
		"t0", 1, "t1", 0, "t2", 0, "t3", 0, "t4", 0, "t5", 0, "t6", 0, "t7", 0, "t8", 0, "t9", 0,
		"t10", 0, "t11", 0, "t12", 0, "t13", 0, "t14", 0, "t15", 0, "t16", 0, "t17", 0, "t18", 0, "t19", 0,
		"t20", 0, "t21", 0, "t22", 0, "t23", 0, "t24", 0, "t25", 0, "t26", 0, "t27", 0, "t28", 0, "t29", 0,
		"t30", 0, "t31", 0, "t32", 0, "t33", 0, "t34", 0, "t35", 0, "t36", 0, "t37", 0, "t38", 0, "t39", 0,
		"t40", 0, "t41", 0, "t42", 0, "t43", 0, "t44", 0, "t45", 0, "t46", 0, "t47", 0, "t48", 0, "t49", 0,
		"t50", 0, "t51", 0, "t52", 0, "t53", 0, "t54", 0, "t55", 0, "t56", 0, "t57", 0, "t58", 0, "t59", 0)
elseif (elapsed_time > 0) then -- Inside the period
	for i = 0, elapsed_time do
		local index = redis.call("HINCRBY", ipkey, "idx", 1)
		if (index >= 60) then index = redis.call("HSET", ipkey, "idx", 0) end
		local curr_index = "t" .. index
		local req_count_at_tx = redis.call("HGET", ipkey, curr_index)
		redis.call("HINCRBY", ipkey, "sum", -req_count_at_tx)
		redis.call("HSET", ipkey, curr_index, 0)
	end
	local curr_index = "t" .. redis.call("HGET", ipkey, "idx")
	redis.call("HSET", ipkey, curr_index, 1)
	redis.call("HINCRBY", ipkey, "sum", 1)
elseif (elapsed_time == 0) then -- Latest tx
	local curr_index = "t" .. redis.call("HGET", ipkey, "idx")
	redis.call("HINCRBY", ipkey, curr_index, 1)
	redis.call("HINCRBY", ipkey, "sum", 1)
end
redis.call("HSET", ipkey, "ts", time)
redis.call("EXPIRE", ipkey, 60)
local sum = tonumber(redis.call("HGET", ipkey, "sum"))
local limit = tonumber(redis.call("GET", ARGV[1] .. "_limit"))
if (limit ~= nil and sum >= limit) then return 1 else return 0 end