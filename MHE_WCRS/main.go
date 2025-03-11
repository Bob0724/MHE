package main

import (
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
	i         int 
	sk        *rlwe.SecretKey
	shareOut  mhe.PublicKeyGenShare
	pt        *rlwe.Plaintext
	ct        *rlwe.Ciphertext
	ptpart    *rlwe.Plaintext
	ptaddpart *rlwe.Plaintext
	pk        *rlwe.PublicKey
	input     []uint64
}

type Computer struct {
	ringQ *ring.Ring
}

func main() {

	var start, end time.Time
	var duration time.Duration
	var durationall time.Duration


	fmt.Println("> Parameter initialization Phase")
	start = time.Now()

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

	// fmt.Println("Parameters created successfully:", params)


	fmt.Println("> Private key generation Phase")
	start = time.Now()

	kgen := rlwe.NewKeyGenerator(params)



	// fmt.
	// Println("输入参与方数量：")
	N := 100
	//_, err = fmt.Scanln(&N)
	if err != nil {
		fmt.Println("Error reading input:", err)
		return
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
	fmt.Printf("Private key generation time: %s\n", duration)


	fmt.Println("> Public key generation Phase")
	start = time.Now()

	ckg := mhe.NewPublicKeyGenProtocol(params)

	for i := 0; i < N; i++ {

		parties[i].pk = rlwe.NewPublicKey(params)


		crs, err := sampling.NewPRNG()
		if err != nil {
			fmt.Println("Error creating CRS:", err)
			return
		}

		crpi := ckg.SampleCRP(crs)

		parties[i].shareOut = ckg.AllocateShare()
		ckg.GenShare(parties[i].sk, crpi, &parties[i].shareOut) //p_(1,i)*s_i+e_i
		ckg.GenPublicKey(parties[i].shareOut, crpi, parties[i].pk)
	}


	// fmt.Println("Public key generated successfully!")
	end = time.Now()
	duration = end.Sub(start)
	durationall += duration
	fmt.Printf("Public key generation Phase time: %s\n", duration)


	fmt.Println("> Encrypt Phase")
	start = time.Now()

	encoder := heint.NewEncoder(params)

	for i := 0; i < N; i++ {

		encryptor := rlwe.NewEncryptor(params, parties[i].pk)

		parties[i].pt = heint.NewPlaintext(params, params.MaxLevel())
		// fmt.Printf("Party %d: Plaintext generated successfully\n", i)

		parties[i].ct = heint.NewCiphertext(params, 1, params.MaxLevel())

		parties[i].input = make([]uint64, params.N())
		for j := range parties[i].input {
			parties[i].input[j] = uint64(i)
		}

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
		parties[i].ct = extendCiphertext(parties[i].ct, N, params, i)
	}
	end = time.Now()
	duration = end.Sub(start)
	durationall += duration
	fmt.Printf("time: %s\n", duration)


	fmt.Println("> Computation Phase")
	start = time.Now()
	ctadd := heint.NewCiphertext(params, 1, params.MaxLevel())
	ctadd = extendCiphertext(ctadd, N, params, 2)
	computer := NewComputer(params)
	computer.Add(parties[1].ct, parties[2].ct, ctadd, N)
	// fmt.Printf("The sum of parties[1].ct and parties[2].ct generated successfully!\n")

	end = time.Now()
	duration = end.Sub(start)
	durationall += duration
	fmt.Printf("time: %s\n", duration)


	fmt.Println("> Decrypt Phase")
	start = time.Now()
	for j := 0; j < N; j++ {
		//解密份额的和
		parties[j].ct = reCiphertext(parties[j].ct, N, params, j)
		decryptor := rlwe.NewDecryptor(params, parties[j].sk)
		parties[j].ptpart = heint.NewPlaintext(params, params.MaxLevel())
		decryptor.Decryptpart(parties[j].ct, parties[j].ptpart)
		decryptor.Decryptall(parties[j].ct, parties[j].ptpart) //全部解密

		res := make([]uint64, params.MaxSlots())
		if err := encoder.Decode(parties[j].ptpart, res); err != nil {
			panic(err)
		}
		fmt.Printf("\t%v...%v\n", res[:8], res[params.N()-8:]) //打印前八个元素和后八个元素

		// fmt.Printf("Party %d: NewPlaintext generated successfully!\n", j)
	}
	//end = time.Now()
	//duration = end.Sub(start)
	//durationall += duration
	//fmt.Printf("time: %s\n", duration)


	//start = time.Now()

	hisigema := heint.NewPlaintext(params, params.MaxLevel())
	for i := 1; i < N; i++ {
		ctaddi := reCiphertext(ctadd, N, params, i)
		decryptor := rlwe.NewDecryptor(params, parties[i].sk)
		parties[i].ptaddpart = heint.NewPlaintext(params, params.MaxLevel())
		decryptor.Decryptpart(ctaddi, parties[i].ptaddpart)  //部分解密
		decryptor.Decryptadd(parties[i].ptaddpart, hisigema) //求和
	}
	ctaddzero := ctaddzero(ctadd, N, params)
	decryptor := rlwe.NewDecryptor(params, parties[0].sk)
	decryptor.Decryptall(ctaddzero, hisigema) //全部解密
	res := make([]uint64, params.MaxSlots())
	if err := encoder.Decode(hisigema, res); err != nil {
		panic(err)
	}
	fmt.Println("The decryption result of ct_add:")
	fmt.Printf("\t%v...%v\n", res[:8], res[params.N()-8:]) //打印前八个元素和后八个元素
	end = time.Now()
	duration = end.Sub(start)
	durationall += duration
	fmt.Printf("time: %s\n", duration)
	fmt.Printf("all time: %s\n", durationall)

}

func extendCiphertext(ct *rlwe.Ciphertext, N int, params heint.Parameters, i int) *rlwe.Ciphertext {
	ctext := heint.NewCiphertext(params, N, params.MaxLevel())
	ctext.Value[0] = ct.Value[0]
	ctext.Value[i+1] = ct.Value[1]
	return ctext
}

func reCiphertext(ct *rlwe.Ciphertext, N int, params heint.Parameters, i int) *rlwe.Ciphertext {
	ctre := heint.NewCiphertext(params, 1, params.MaxLevel())
	ctre.Value[0] = ct.Value[0]
	ctre.Value[1] = ct.Value[i+1]
	return ctre
}

func ctaddzero(ct *rlwe.Ciphertext, N int, params heint.Parameters) *rlwe.Ciphertext {
	ctzero := heint.NewCiphertext(params, 1, params.MaxLevel())
	ctzero.Value[0] = ct.Value[0]
	return ctzero
}

func (c Computer) Add(ct1 *rlwe.Ciphertext, ct2 *rlwe.Ciphertext, ctadd *rlwe.Ciphertext, N int) {
	level := ct1.Level()
	ringQ := c.ringQ.AtLevel(level)
	for i := 0; i < len(ct1.Value); i++ {
		ringQ.Add(ct1.Value[i], ct2.Value[i], ctadd.Value[i])
	}
}

func NewComputer(params heint.Parameters) *Computer {
	return &Computer{
		ringQ: params.RingQ(),
	}
}
