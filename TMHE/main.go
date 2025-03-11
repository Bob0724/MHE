package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// 参与方
type party struct {
	i        int //表示第i个参与方
	sk       *rlwe.SecretKey
	shareOut mhe.PublicKeyGenShare // 公钥生成协议的份额
	pt       *rlwe.Plaintext
	ct       *rlwe.Ciphertext
	ptpart   *rlwe.Plaintext
	input    []uint64

	Thresholdizer     mhe.Thresholdizer
	share             mhe.ShamirSecretShare
	ShamirPoly        mhe.ShamirPolynomial
	ShamirPublicPoint mhe.ShamirPublicPoint
	mhe.Combiner
}

type Computer struct {
	ringQ *ring.Ring
}

var flagO = flag.Int("o", 0, "the number of online parties")

func main() {
	var start, end time.Time
	var duration time.Duration
	var durationall time.Duration
	//*****初始化参数*****
	fmt.Println("> Parameter initialization Phase")
	start = time.Now()
	// 创建参数字面量
	params, err := heint.NewParametersFromLiteral(heint.ParametersLiteral{
		LogN:             15,
		LogQ:             []int{54, 54, 54},
		LogP:             []int{55},
		PlaintextModulus: 65537,
	})
	if err != nil {
		fmt.Println("Error creating parameters:", err)
		return
	}
	end = time.Now()
	duration = end.Sub(start)
	durationall += duration
	fmt.Printf("Parameter initialization time: %s\n", duration)
	// 打印参数信息
	// fmt.Println("Parameters created successfully:", params)

	//*****私钥生成*****
	fmt.Println("> Private key generation Phase")
	start = time.Now()
	// 创建密钥生成器
	kgen := rlwe.NewKeyGenerator(params)

	//假设有N个参与方，自定义输入
	// fmt.Println("输入参与方数量：")
	N := 100
	//_, err = fmt.Scanln(&N)
	// if err != nil {
	// 	fmt.Println("Error reading input:", err)
	// 	return
	// }
	var o int
	if *flagO <= 0 {
		o = N
	} else {
		o = *flagO
	}

	parties := make([]*party, N)
	for i := 0; i < N; i++ {
		sk := kgen.GenSecretKeyNew()
		parties[i] = &party{i: i, sk: sk}
		// fmt.Printf("Party %d: Secret key generated successfully\n", i)
	}
	end = time.Now()
	duration = end.Sub(start)
	durationall += duration
	fmt.Printf("Private key generation Phase time: %s\n", duration)

	//*****秘密共享*****
	fmt.Println("> Shamir Secret Share Phase")
	start = time.Now()
	//秘密共享的初始化操作
	shamirPublicPoints := make([]mhe.ShamirPublicPoint, 0)
	t := 95
	//_, err = fmt.Scanln(&t)
	// if err != nil {
	// 	fmt.Println("Error reading input:", err)
	// 	return
	// }
	for i := 0; i < N; i++ {
		parties[i].Thresholdizer = mhe.NewThresholdizer(params)
		parties[i].share = parties[i].Thresholdizer.AllocateThresholdSecretShare()
		var err error
		parties[i].ShamirPoly, err = parties[i].Thresholdizer.GenShamirPolynomial(t, parties[i].sk)
		if err != nil {
			panic(err)
		}
		parties[i].ShamirPublicPoint = mhe.ShamirPublicPoint(i + 1)
		shamirPublicPoints = append(shamirPublicPoints, parties[i].ShamirPublicPoint)
	}
	if t != N {

		for _, pi := range parties {
			params_rlwe := rlwe.ParameterProvider(params)
			pi.Combiner = mhe.NewCombiner(*params_rlwe.GetRLWEParameters(), pi.ShamirPublicPoint, shamirPublicPoints, t)
		}

		shares := make(map[*party]map[*party]mhe.ShamirSecretShare, len(parties))

		for _, pi := range parties {

			shares[pi] = make(map[*party]mhe.ShamirSecretShare)

			for _, pj := range parties {
				share := pi.Thresholdizer.AllocateThresholdSecretShare()
				pi.Thresholdizer.GenShamirSecretShare(pj.ShamirPublicPoint, pi.ShamirPoly, &share)
				shares[pi][pj] = share
			}

		}

		for _, pi := range parties {
			for _, pj := range parties {
				share := shares[pj][pi]
				if err := pi.Thresholdizer.AggregateShares(pi.share, share, &pi.share); err != nil {
					panic(err)
				}
			}
		}

	}
	end = time.Now()
	duration = end.Sub(start)
	// durationall += duration
	fmt.Printf("share time: %s\n", duration)

	//*****公钥生成*****
	fmt.Println("> Public key generation Phase")
	// 创建公钥生成协议实例
	start = time.Now()

	o = t
	parties_oline := parties[:o]

	// 重构
	for i := 0; i < t; i++ {
		parties[i].sk = parties[i].combine(t, N, parties_oline, params)
	}
	ckg := mhe.NewPublicKeyGenProtocol(params)

	// 生成CRS
	crs, err := sampling.NewPRNG()
	if err != nil {
		fmt.Println("Error creating CRS:", err)
		return
	}
	//从CRS中抽样记作CRP
	crp := ckg.SampleCRP(crs)

	// fmt.Println("CRS generated successfully!")
	// 生成公钥
	pk := rlwe.NewPublicKey(params)
	// 假设这是从参与方处接收到的最终聚合的共享
	roundShare := ckg.AllocateShare()

	for i := 0; i < t; i++ {
		parties[i].shareOut = ckg.AllocateShare()
		ckg.GenShare(parties[i].sk, crp, &parties[i].shareOut)
		ckg.AggregateShares(parties[i].shareOut, roundShare, &roundShare)
	}

	ckg.GenPublicKey(roundShare, crp, pk)
	//公钥生成成功
	// fmt.Println("Public key generated successfully!")
	end = time.Now()
	duration = end.Sub(start)
	durationall += duration
	fmt.Printf("Public key generation Phase time: %s\n", duration)

	//*****加密*****
	fmt.Println("> Encrypt Phase")
	start = time.Now()
	//初始化加密生成器和编码生成器
	encryptor := rlwe.NewEncryptor(params, pk)
	encoder := heint.NewEncoder(params)
	//生成明文
	for i := 0; i < N; i++ {
		//明文初始化
		parties[i].pt = heint.NewPlaintext(params, params.MaxLevel())
		// fmt.Printf("Party %d: Plaintext generated successfully\n", i)
		//密文初始化
		parties[i].ct = heint.NewCiphertext(params, 1, params.MaxLevel())
		//Encode编码大小不超过N的整数切片，该切片传入用于判断大小
		parties[i].input = make([]uint64, params.N())
		for j := range parties[i].input {
			parties[i].input[j] = uint64(i)
		}
		//编码
		if err := encoder.Encode(parties[i].input, parties[i].pt); err != nil {
			panic(err)
		}
		res0 := make([]uint64, params.MaxSlots())
		if err := encoder.Decode(parties[i].pt, res0); err != nil {
			panic(err)
		}
		fmt.Printf("\t%v...%v\n", res0[:8], res0[params.N()-8:]) //打印前八个元素和后八个元素

		// fmt.Printf("Party %d: Plaintext encoded successfully!\n", i)
		//加密
		if err := encryptor.Encrypt(parties[i].pt, parties[i].ct); err != nil {
			panic(err)
		}
		// fmt.Printf("Party %d: Ciphertext generated successfully!\n", i)
		//parties[i].ct = extendCiphertext(parties[i].ct, N, params, i)
	}
	end = time.Now()
	duration = end.Sub(start)
	durationall += duration
	fmt.Printf("Encrypt Phase time: %s\n", duration)

	//*****同态加法*****
	fmt.Println("> Computation Phase")
	start = time.Now()
	ctadd := heint.NewCiphertext(params, 1, params.MaxLevel())
	computer := NewComputer(params)
	computer.Add(parties[1].ct, parties[2].ct, ctadd, N)
	// fmt.Printf("The sum of parties[1].ct and parties[2].ct generated successfully!\n")

	end = time.Now()
	duration = end.Sub(start)
	durationall += duration
	fmt.Printf("计算time: %s\n", duration)

	//*****解密*****
	fmt.Println("> Decrypt Phase")
	start = time.Now()
	//重构
	for i := 0; i < t; i++ {
		parties[i].sk = parties[i].combine(t, N, parties_oline, params)
	}

	// for i := 0; i < N; i++ {
	// 	parties[i].ct = reCiphertext(parties[i].ct, N, params, i)
	// }

	for j := 0; j < N; j++ {
		//解密分额的和
		hisigema := heint.NewPlaintext(params, params.MaxLevel())

		for i := 0; i < t; i++ {
			parties[i].ptpart = heint.NewPlaintext(params, params.MaxLevel())
			decryptor := rlwe.NewDecryptor(params, parties[i].sk)
			decryptor.Decryptpart(parties[j].ct, parties[i].ptpart) //部分解密

			decryptor.Decryptadd(parties[i].ptpart, hisigema) //求和
		}
		decryptor := rlwe.NewDecryptor(params, parties[j].sk)
		decryptor.Decryptall(parties[j].ct, hisigema) //全部解密

		res := make([]uint64, params.MaxSlots())
		if err := encoder.Decode(hisigema, res); err != nil {
			panic(err)
		}
		fmt.Printf("\t%v...%v\n", res[:8], res[params.N()-8:]) //打印前八个元素和后八个元素

		// fmt.Printf("Party %d: NewPlaintext generated successfully!\n", j)
	}

	//*****同态加法解密*****
	//解密份额的和
	hisigema := heint.NewPlaintext(params, params.MaxLevel())

	for i := 0; i < t; i++ {
		ptaddpart := heint.NewPlaintext(params, params.MaxLevel())
		decryptor := rlwe.NewDecryptor(params, parties[i].sk)
		decryptor.Decryptpart(ctadd, ptaddpart) //部分解密

		decryptor.Decryptadd(ptaddpart, hisigema) //求和
	}
	decryptor := rlwe.NewDecryptor(params, parties[1].sk)
	decryptor.Decryptall(ctadd, hisigema) //全部解密

	res := make([]uint64, params.MaxSlots())
	if err := encoder.Decode(hisigema, res); err != nil {
		panic(err)
	}
	fmt.Printf("ctadd 解密得%v...%v\n", res[:8], res[params.N()-8:]) //打印前八个元素和后八个元素

	// fmt.Printf("Party %d: NewPlaintext generated successfully!\n", j)
	end = time.Now()
	duration = end.Sub(start)
	durationall += duration
	fmt.Printf("解密time: %s\n", duration)

	fmt.Printf("all time: %s\n", durationall)
}

// func extendCiphertext(ct *rlwe.Ciphertext, N int, params heint.Parameters, i int) *rlwe.Ciphertext {
// 	ctext := heint.NewCiphertext(params, N, ct.Level())
// 	ctext.Value[0] = ct.Value[0]
// 	ctext.Value[i+1] = ct.Value[1]
// 	return ctext
// }

// func reCiphertext(ct *rlwe.Ciphertext, N int, params heint.Parameters, i int) *rlwe.Ciphertext {
// 	ctext := heint.NewCiphertext(params, 1, ct.Level())
// 	ctext.Value[0] = ct.Value[0]
// 	ctext.Value[1] = ct.Value[i+1]
// 	return ctext
// }

func (p *party) combine(t int, N int, parties_oline []*party, params heint.Parameters) *rlwe.SecretKey {

	var sk *rlwe.SecretKey
	if t == N {
		sk = p.sk
	} else {
		activePublicPoint := make([]mhe.ShamirPublicPoint, 0)
		for _, pi := range parties_oline {
			activePublicPoint = append(activePublicPoint, pi.ShamirPublicPoint)
		}
		sk = rlwe.NewSecretKey(params)
		if err := p.Combiner.GenAdditiveShare(activePublicPoint, p.ShamirPublicPoint, p.share, sk); err != nil {
			panic(err)
		}

	}
	return sk
}
func NewComputer(params heint.Parameters) *Computer {
	return &Computer{
		ringQ: params.RingQ(),
	}
}

func (c Computer) Add(ct1 *rlwe.Ciphertext, ct2 *rlwe.Ciphertext, ctadd *rlwe.Ciphertext, N int) {
	level := ct1.Level()
	ringQ := c.ringQ.AtLevel(level)
	for i := 0; i < len(ct1.Value); i++ {
		ringQ.Add(ct1.Value[i], ct2.Value[i], ctadd.Value[i])
	}
}
